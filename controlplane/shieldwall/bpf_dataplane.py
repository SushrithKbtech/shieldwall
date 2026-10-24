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
import time
from collections import defaultdict

from .classifier import Classifier
from .detectors import Detector
from .features import entropy
from .mitigation import MitigationConfig, MitigationController
from .models import AMP_PORTS, Features, Rule, ip_str
from .sketches import BloomFilter, CountMinSketch, HyperLogLog

RULE_SYN_ONLY, RULE_UNTRUSTED, RULE_FRAG = 0x01, 0x02, 0x04
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
        self.blocked: set[tuple[int, int]] = set()
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
        flags = (RULE_SYN_ONLY if r.syn_only else 0) | (RULE_UNTRUSTED if r.untrusted_only else 0) |             (RULE_FRAG if r.frag_only else 0)
        return struct.pack("<BBHHH", r.proto, flags, r.sport, r.dport, 0)

    def sync_blocklist(self, rules: list[Rule]) -> None:
        """Source rules (heavy hitters) live in the LPM blocklist map, not the port rules map."""
        want = {(bin(r.src_mask).count("1"), r.src) for r in rules if r.src_mask}
        for plen, addr in want - self.blocked:
            key = struct.pack("<I", plen) + struct.pack(">I", addr)
            _bpftool("map", "update", "name", "blocklist", "key", *_hex(key), "value", *_hex(struct.pack("<Q", 0)))
        for plen, addr in self.blocked - want:
            _bpftool("map", "delete", "name", "blocklist", "key", *_hex(struct.pack("<I", plen) + struct.pack(">I", addr)))
        self.blocked = want

    def sync_rules(self, rules: list[Rule], ttl_s: int) -> None:
        self.sync_blocklist(rules)
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
        )
        heavy = cms.top(1)
        if heavy and pps:
            f.top_src, f.top_share = heavy[0][0], min(heavy[0][1], pps) / pps
            f.top_src_new = f.top_src not in seen
        self.t += 1
        return f, trust_candidates


def run_live(iface: str, dry_run: bool = False, obj: str = "bpf/xdp_filter.o") -> None:
    dp = BPFDataPlane(iface, obj)
    cfg = MitigationConfig(dry_run=dry_run)
    dp.attach(enforce=not dry_run)
    for cidr in cfg.allowlist:
        dp.allow(cidr)
    det, cls, ctl, seen = Detector(), Classifier(), MitigationController(cfg), BloomFilter(200_000)
    print(f"ShieldWall attached to {iface} ({'dry-run' if dry_run else 'enforcing'}). Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
            f, candidates = dp.read_features(seen)
            v = det.update(f)
            c = cls.classify(f) if v.anomalous else None
            for a in ctl.step(f.t, v.anomalous, c, f, v.baseline_pps, {}, {}):
                print(f"[t={f.t}] {a.kind}: {a.detail}")
            dp.sync_rules(ctl.enforced_rules(), cfg.rule_ttl)
            if not v.anomalous and not any(v.votes.values()):
                cls.learn(f)
                for addr in candidates:  # only learned in calm windows, never during an attack
                    dp.trust(addr)
                    seen.add(struct.unpack(">I", struct.pack("<I", addr))[0])
            print(f"t={f.t} pps={f.pps:,.0f} z={v.zscore:.1f} cusum={v.cusum:.1f} "
                  f"{'ALERT ' + c.label if c else 'ok'}")
    except KeyboardInterrupt:
        pass
    finally:
        dp.detach()
