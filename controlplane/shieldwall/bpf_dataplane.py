"""Linux data plane: drive the real XDP program in bpf/xdp_filter.c through bpftool.

Tested end to end on a Linux 6.x kernel (WSL2) over a veth pair: see tests/xdp_kernel_test.sh.

    sudo python -m shieldwall live --iface eth0 [--dry-run]
"""
from __future__ import annotations

import json
import math
import socket
import struct
import subprocess
import threading
import time
from collections import defaultdict

from .cascade import CascadeClassifier
from .detectors import Detector
from .features import entropy
from .mitigation import MitigationConfig, MitigationController
from .models import AMP_PORTS, Features, Packet, Rule, ip_str
from .sketches import BloomFilter, CountMinSketch, HyperLogLog
from .store import EventStore

RULE_SYN_ONLY, RULE_UNTRUSTED, RULE_FRAG, RULE_SYNACK = 0x01, 0x02, 0x04, 0x08
ACTIONS = {"drop": 1, "rate_limit": 2}


def _bpftool(*args: str):
    out = subprocess.run(["bpftool", "-j", *args], check=True, capture_output=True, text=True).stdout
    return json.loads(out) if out.strip() else None


def _hex(b: bytes) -> list[str]:
    return ["hex", *(f"{x:02x}" for x in b)]


def _sum_percpu(entry: dict) -> dict:
    """bpftool prints per-CPU values as a list; add them up field by field."""
    total: dict = defaultdict(int)
    for cpu in entry.get("formatted", entry).get("values", []):
        val = cpu.get("value", cpu)
        if isinstance(val, dict):
            for k, v in val.items():
                total[k] += int(v)
        else:
            total["value"] += int(val)
    return total


class BPFDataPlane:
    def __init__(self, iface: str, obj: str = "bpf/xdp_filter.o", mode: str = "xdpgeneric"):
        self.iface, self.obj, self.mode = iface, obj, mode
        self.prev: dict = {}
        self.prev_src: dict[int, dict] = {}
        self.prev_sport: dict[int, int] = {}
        self.written: dict[bytes, int] = {}
        self.blocked: dict[tuple[int, int], int] = {}
        self.t = 0

    def attach(self, enforce: bool = True) -> None:
        subprocess.run(["ip", "link", "set", "dev", self.iface, self.mode, "obj", self.obj, "sec", "xdp"], check=True)
        self.set_enforce(enforce)

    def detach(self) -> None:
        subprocess.run(["ip", "link", "set", "dev", self.iface, self.mode, "off"], check=False)

    def set_enforce(self, enforce: bool) -> None:
        _bpftool("map", "update", "name", "config", "key", *_hex(struct.pack("<I", 0)),
                 "value", *_hex(struct.pack("<I", int(enforce))))

    def allow(self, cidr: str) -> None:
        net, plen = cidr.split("/")
        key = struct.pack("<I", int(plen)) + socket.inet_aton(net)
        _bpftool("map", "update", "name", "allowlist", "key", *_hex(key), "value", "01")

    def trust(self, addr_be: int) -> None:
        _bpftool("map", "update", "name", "trusted", "key", *_hex(struct.pack("<I", addr_be)), "value", "01")

    # -- rules ------------------------------------------------------------------
    @staticmethod
    def _rule_key(r: Rule) -> bytes:
        flags = (RULE_SYN_ONLY if r.syn_only else 0) | (RULE_UNTRUSTED if r.untrusted_only else 0) |             (RULE_FRAG if r.frag_only else 0) | (RULE_SYNACK if r.synack_only else 0)
        return struct.pack("<BBHHH", r.proto, flags, r.sport, r.dport, 0)

    def sync_blocklist(self, rules: list[Rule], ttl_s: int = 60) -> None:
        """Source rules (heavy hitters) live in the LPM blocklist map, with their own expiry in the kernel."""
        want = {(bin(r.src_mask).count("1"), r.src): r for r in rules if r.src_mask}
        now = time.monotonic_ns()
        for (plen, addr), r in want.items():
            if (plen, addr) in self.blocked and self.blocked[(plen, addr)] - now > ttl_s * 500_000_000:
                continue
            expires = now + ttl_s * 1_000_000_000
            key = struct.pack("<I", plen) + struct.pack(">I", addr)
            val = struct.pack("<IIQQQQ", int(r.rate_pps) if r.action == "rate_limit" else 0, 0, 0, now, expires, 0)
            _bpftool("map", "update", "name", "blocklist", "key", *_hex(key), "value", *_hex(val))
            self.blocked[(plen, addr)] = expires
        for plen, addr in list(self.blocked.keys() - want.keys()):
            _bpftool("map", "delete", "name", "blocklist", "key", *_hex(struct.pack("<I", plen) + struct.pack(">I", addr)))
            del self.blocked[(plen, addr)]

    def sync_rules(self, rules: list[Rule], ttl_s: int) -> None:
        self.sync_blocklist(rules, ttl_s)
        rules = [r for r in rules if not r.src_mask]
        want = {self._rule_key(r): r for r in rules}
        now = time.monotonic_ns()  # bpf_ktime_get_ns() is CLOCK_MONOTONIC
        for key, r in want.items():
            # (re)write only new rules or ones close to expiry, so hit counters and buckets survive
            if key in self.written and self.written[key] - now > ttl_s * 500_000_000:
                continue
            expires = now + ttl_s * 1_000_000_000
            val = struct.pack("<IIQQQQ", ACTIONS[r.action], int(r.rate_pps), 0, now, expires, 0)
            _bpftool("map", "update", "name", "rules", "key", *_hex(key), "value", *_hex(val))
            self.written[key] = expires
        for key in list(self.written.keys() - want.keys()):
            _bpftool("map", "delete", "name", "rules", "key", *_hex(key))
            del self.written[key]

    # -- one window of counters -> features --------------------------------------
    def read_features(self, seen: BloomFilter) -> tuple[Features, list[int]]:
        stats = _sum_percpu((_bpftool("map", "dump", "name", "stats") or [{}])[0])
        delta = {k: v - self.prev.get(k, 0) for k, v in stats.items()}
        self.prev = stats

        # the maps hold running totals; this window is the difference from the last read
        # Only keys still in the (LRU) maps are kept, so memory stays bounded under spoofed floods.
        sports, prev_sport = {}, {}
        for e in _bpftool("map", "dump", "name", "udp_sport_count") or []:
            port = struct.unpack("<H", bytes(int(x, 16) for x in e["key"]))[0]
            total = _sum_percpu(e)["value"]
            d = total - self.prev_sport.get(port, 0)
            if d < 0:  # evicted and re-created since the last read
                d = total
            if d > 0:
                sports[port] = d
            prev_sport[port] = total
        self.prev_sport = prev_sport
        srcs, prev_src = {}, {}
        for e in _bpftool("map", "dump", "name", "src_count") or []:
            addr = struct.unpack("<I", bytes(int(x, 16) for x in e["key"]))[0]
            cur = {k: int(v) for k, v in e.get("formatted", e)["value"].items()}
            old = self.prev_src.get(addr, {})
            d = {k: v - old.get(k, 0) for k, v in cur.items()}
            if d["pkts"] < 0:  # evicted and re-created since the last read
                d = cur
            if d["pkts"] > 0:
                srcs[addr] = d
            prev_src[addr] = cur
        self.prev_src = prev_src

        pps = float(delta.get("pkts", 0))
        hll, cms = HyperLogLog(), CountMinSketch(top_k=5)
        new_w = 0.0
        trust_candidates = []
        for addr, st in srcs.items():
            host = struct.unpack(">I", struct.pack("<I", addr))[0]
            hll.add(host)
            cms.add(host, st["pkts"])
            if host not in seen:
                new_w += st["pkts"]
            # completed a TCP handshake, or a steady sender (covers UDP players such as Bedrock)
            if st["ack"] or st["pkts"] >= 3:
                trust_candidates.append(addr)
        amp = {p: n for p, n in sports.items() if p in AMP_PORTS}
        amp_port = max(amp, key=amp.get) if amp else None
        f = Features(
            t=self.t, pps=pps, bps=float(delta.get("bytes", 0)) * 8,
            syn_pps=float(delta.get("syn", 0)), ack_pps=float(delta.get("ack", 0)),
            udp_share=delta.get("udp", 0) / pps if pps else 0.0,
            syn_ack_ratio=delta.get("syn", 0) / max(delta.get("ack", 0), 1),
            amp_share=sum(amp.values()) / pps if pps else 0.0, amp_port=amp_port,
            unique_sources=hll.count(), new_source_share=new_w / pps if pps else 0.0,
            src_entropy=entropy(st["pkts"] for st in srcs.values()),
            dport_entropy=math.nan,
            top_talkers=[(ip_str(k), v) for k, v in cms.top(5)],
            frag_share=delta.get("frag", 0) / pps if pps else 0.0,
            amp_ports=sorted((p for p, n in amp.items() if pps and n / pps >= 0.05), key=lambda p: -amp[p]),
            amp_ports_seen=sorted((p for p, n in amp.items() if pps and n / pps >= 0.005), key=lambda p: -amp[p]),
            synack_pps=float(delta.get("synack", 0)),
        )
        heavy = cms.top(1)
        if heavy and pps:
            f.top_src, f.top_share = heavy[0][0], min(heavy[0][1], pps) / pps
            f.top_src_new = f.top_src not in seen
        self.t += 1
        return f, trust_candidates


class PacketSampler:
    """A small sample of the packets the XDP program let through, read from an AF_PACKET socket.

    The kernel maps only hold totals, but the Tier 3 analyst's rule has to be tested against
    real packets (mitigation.validate_suggestion). XDP runs first, so dropped packets never
    reach the socket; the analyst only investigates traffic no rule is stopping yet."""

    def __init__(self, iface: str, per_window: int = 2000):
        from .pcap import ETH, _link

        self._parse = lambda frame: _link(frame, ETH, 0.0, len(frame))
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        self.sock.bind((iface, 0))
        self.sock.settimeout(0.2)
        self.per_window, self.buf, self.lock = per_window, [], threading.Lock()
        self.room = threading.Event()
        self.room.set()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        while True:
            self.room.wait()  # full: let the socket buffer overflow instead of spinning on a flood
            try:
                frame = self.sock.recv(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            p = self._parse(frame)
            if p is not None:
                with self.lock:
                    self.buf.append(p)
                    if len(self.buf) >= self.per_window:
                        self.room.clear()

    def take(self, pps: float) -> list[Packet]:
        """This window's sample, each packet weighted to stand for its share of the kernel's count."""
        with self.lock:
            buf, self.buf = self.buf, []
            self.room.set()
        w = pps / len(buf) if buf else 0.0
        return [Packet(p.src, p.sport, p.dport, p.proto, p.flags, p.size, w, frag=p.frag) for p in buf]


class LiveLoop:
    """One control-loop tick against the real kernel maps: read -> detect -> classify -> act -> sync.

    The full cascade runs here too: statistics, fingerprints, the ML model, and (with a packet
    sampler) the Tier 3 analyst, whose rules are validated against sampled traffic and kept in
    dry-run, exactly as in the simulator engine."""

    def __init__(self, dp: BPFDataPlane, cfg: MitigationConfig, sampler: PacketSampler | None = None,
                 analyst_async: bool = True):
        from .engine import TRUST_AFTER

        self.dp, self.cfg, self.trust_after = dp, cfg, TRUST_AFTER
        self.det, self.cls, self.ctl = Detector(), CascadeClassifier(), MitigationController(cfg)
        self.seen = BloomFilter(200_000)
        self.calm_seen: dict[int, int] = {}
        # what the Tier 3 analyst works from (same names as the simulator engine)
        self.sampler, self.analyst_async = sampler, analyst_async
        self.lock = threading.RLock()
        self.store = EventStore()
        self.trusted: set[int] = set()
        self.attack_sample: list[Packet] = []
        self.calm_sample: list[Packet] = []
        self.incident: dict | None = None
        self.last_incident: dict | None = None
        self.analyst_results: list[dict] = []
        self.t = 0
        self._incidents = 0

    @property
    def controller(self) -> MitigationController:
        return self.ctl

    def tick(self):
        from .engine import profile

        with self.lock:
            f, candidates = self.dp.read_features(self.seen)
            self.t = f.t
            samples = self.sampler.take(f.pps) if self.sampler else []
            v = self.det.update(f)
            c = self.cls.classify(f) if v.anomalous else None
            actions = self.ctl.step(f.t, v.anomalous, c, f, v.baseline_pps, {}, {})
            self.dp.sync_rules(self.ctl.enforced_rules(), self.cfg.rule_ttl)
            calm = not v.anomalous and not any(v.votes.values())
            if v.anomalous:
                if self.incident is None:
                    self._incidents += 1
                    self.incident = {"id": self._incidents, "evidence": c.evidence, "peak": 0.0, "profile": {}}
                if f.pps >= self.incident["peak"] and samples:
                    self.incident.update(peak=f.pps, profile=profile(f, samples))
                    self.attack_sample = samples
                if c.needs_llm and self.sampler and self.attack_sample and not self.incident.get("investigated"):
                    self.incident["investigated"] = True
                    self._investigate(c)
            elif calm and self.incident is not None:
                self.last_incident, self.incident = self.incident, None
            if calm:
                if samples:
                    self.calm_sample = samples
                self.cls.learn(f)
                for addr in candidates:  # only learned in calm windows, never during an attack
                    host = struct.unpack(">I", struct.pack("<I", addr))[0]
                    self.seen.add(host)
                    n = self.calm_seen.get(addr, 0) + 1
                    self.calm_seen[addr] = n
                    if n == self.trust_after:  # trusted only after several separate calm seconds
                        self.dp.trust(addr)
                        self.trusted.add(host)
                if len(self.calm_seen) > 200_000:
                    self.calm_seen.clear()
            return f, v, c, actions

    def _investigate(self, c) -> None:
        """Tier 3 off the hot path: propose one rule, validate it on sampled traffic, keep it in dry-run."""
        def work():
            from .analyst import investigate
            try:
                self.analyst_results.append(investigate(self, evidence=list(c.evidence),
                                                        profile=self.incident.get("profile", {})))
            except Exception as e:  # the analyst must never take the control loop down
                self.analyst_results.append({"proposed": None, "verdict": None, "error": str(e)})

        if self.analyst_async:
            threading.Thread(target=work, daemon=True).start()
        else:
            work()


def run_live(iface: str, dry_run: bool = False, obj: str = "bpf/xdp_filter.o") -> None:
    dp = BPFDataPlane(iface, obj)
    cfg = MitigationConfig(dry_run=dry_run)
    dp.attach(enforce=not dry_run)
    for cidr in cfg.allowlist:
        dp.allow(cidr)
    try:
        sampler = PacketSampler(iface)
    except OSError as e:  # no AF_PACKET access: everything still runs except the Tier 3 analyst
        print(f"packet sampler unavailable ({e}); the Tier 3 analyst is off")
        sampler = None
    loop = LiveLoop(dp, cfg, sampler)
    print(f"ShieldWall attached to {iface} ({'dry-run' if dry_run else 'enforcing'}). Ctrl+C to stop.")
    reported = 0
    try:
        while True:
            time.sleep(1)
            f, v, c, actions = loop.tick()
            for a in actions:
                print(f"[t={f.t}] {a.kind}: {a.detail}")
            for r in loop.analyst_results[reported:]:
                print(f"[t={f.t}] analyst: {(r.get('verdict') or {}).get('verdict', r.get('error'))}")
            reported = len(loop.analyst_results)
            print(f"t={f.t} pps={f.pps:,.0f} z={v.zscore:.1f} cusum={v.cusum:.1f} "
                  f"{'ALERT ' + c.label if c else 'ok'}")
    except KeyboardInterrupt:
        pass
    finally:
        dp.detach()
