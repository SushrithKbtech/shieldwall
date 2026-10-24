"""Traffic simulator + simulated data plane, so the whole loop runs on any laptop.

The real data plane is bpf/xdp_filter.c on Linux. This module reproduces what it
does (count every packet, then drop on a rule match) over *stratified samples*:
each traffic class contributes up to N sampled packets per window, and each sample
carries a weight `w` = how many real packets it represents. That lets us simulate
multi-million-pps floods in pure Python while keeping per-class numbers accurate.

It also models the two physical limits that matter for the evaluation:
  * the internet link (bps) - traffic beyond it is lost before we ever see it
  * the protected server's own capacity (pps) - beyond it, real players time out
"""
from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass, field

from .models import ACK, SYN, TCP, UDP, Packet, Rule, Window

MC_JAVA, MC_BEDROCK = 25565, 19132


def _pool(rng: random.Random, n: int, first_octets: tuple[int, ...]) -> list[int]:
    out = set()
    while len(out) < n:
        a = rng.choice(first_octets)
        out.add((a << 24) | rng.getrandbits(24))
    return list(out)


@dataclass
class AttackSpec:
    kind: str                 # cldap | dns | ntp | syn | udp | flash_crowd
    start: int
    end: int | None = None    # None = until stopped
    pps: float = 200_000
    ramp: int = 2             # seconds to reach full rate


@dataclass
class SimConfig:
    seed: int = 7
    legit_pps: float = 2_000
    players: int = 300
    link_bps: float = 10e9            # 10 Gbps uplink
    server_capacity_pps: float = 60_000
    samples_per_class: int = 400      # legit classes
    attack_samples: int = 2000        # attack classes (enough to see every reflector)
    noise: float = 0.05


@dataclass
class TickResult:
    """What happened to traffic this window (simulator ground truth for metrics)."""
    offered_legit: float = 0.0
    offered_attack: float = 0.0
    legit_after_link: float = 0.0
    passed_legit: float = 0.0
    passed_attack: float = 0.0
    served_legit: float = 0.0
    dropped: float = 0.0
    rule_hits: dict[int, float] = field(default_factory=dict)
    upstream_hits: dict[int, float] = field(default_factory=dict)

    @property
    def legit_served_pct(self) -> float:
        return 100.0 * self.served_legit / self.offered_legit if self.offered_legit else 100.0


class TrafficSim:
    def __init__(self, cfg: SimConfig | None = None):
        self.cfg = cfg or SimConfig()
        self.rng = random.Random(self.cfg.seed)
        r = self.rng
        self.regulars = _pool(r, self.cfg.players, (49, 86, 103, 122, 152, 182))
        self.newcomers = _pool(r, 3_000, (27, 39, 59, 117, 171, 202))
        self.reflectors = {
            "cldap": _pool(r, 1_840, (45, 62, 77, 91, 185, 213)),
            "dns": _pool(r, 2_600, (8, 64, 94, 138, 176, 199)),
            "ntp": _pool(r, 1_200, (31, 46, 89, 141, 195)),
        }
        self.botnet = _pool(r, 6_000, (36, 41, 58, 101, 113, 177, 190))
        self.attacks: list[AttackSpec] = []
        self._cursor: dict[str, int] = {}

    def _next_src(self, kind: str, pool: list[int]) -> int:
        # walk the pool in order so a window's samples cover the whole botnet/reflector set
        i = self._cursor.get(kind, 0)
        self._cursor[kind] = i + 1
        return pool[i % len(pool)]

    # -- scenario control ----------------------------------------------------
    def add_attack(self, spec: AttackSpec) -> None:
        self.attacks.append(spec)

    def stop_all(self, t: int) -> None:
        for a in self.attacks:
            if a.end is None or a.end > t:
                a.end = t

    def active(self, t: int) -> list[AttackSpec]:
        return [a for a in self.attacks if a.start <= t and (a.end is None or t < a.end)]

    def _rate(self, a: AttackSpec, t: int) -> float:
        frac = min(1.0, (t - a.start + 1) / max(1, a.ramp))
        return a.pps * frac

    # -- packet generators ---------------------------------------------------
    def _legit_packet(self, src_pool: list[int], new_conn_prob: float) -> Packet:
        r = self.rng
        src = r.choice(src_pool)
        sport = r.randint(32768, 60999)
        if r.random() < 0.2:
            return Packet(src, sport, MC_BEDROCK, UDP, 0, r.randint(80, 500))
        if r.random() < new_conn_prob:
            return Packet(src, sport, MC_JAVA, TCP, SYN, 60)
        return Packet(src, sport, MC_JAVA, TCP, ACK, r.randint(64, 900))

    def _attack_packet(self, kind: str) -> Packet:
        r = self.rng
        if kind in self.reflectors:
            sport = {"cldap": 389, "dns": 53, "ntp": 123}[kind]
            size = {"cldap": (1200, 1472), "dns": (900, 1472), "ntp": (440, 482)}[kind]
            return Packet(self._next_src(kind, self.reflectors[kind]), sport, r.randint(1024, 65535), UDP, 0,
                          r.randint(*size), legit=False)
        if kind == "syn":  # spoofed: every packet a fresh random source
            src = int(ipaddress.IPv4Address(r.getrandbits(32) | 0x01000000))
            return Packet(src, r.randint(1024, 65535), MC_JAVA, TCP, SYN, 60, legit=False)
        if kind == "udp":
            return Packet(self._next_src(kind, self.botnet), r.randint(1024, 65535), r.randint(1, 65535), UDP, 0,
                          r.randint(512, 1024), legit=False)
        raise ValueError(kind)

    def _class(self, n_pkts: float, gen, k_max: int | None = None) -> list[Packet]:
        if n_pkts <= 0:
            return []
        k = min(k_max or self.cfg.samples_per_class, max(1, int(n_pkts)))
        w = n_pkts / k
        out = [gen() for _ in range(k)]
        for p in out:
            p.w = w
        return out

    def offered(self, t: int) -> list[Packet]:
        """All traffic heading for the server this second, before any filtering."""
        cfg, r = self.cfg, self.rng
        legit = cfg.legit_pps * (1 + r.gauss(0, cfg.noise))
        samples = self._class(legit * 0.95, lambda: self._legit_packet(self.regulars, 0.01))
        samples += self._class(legit * 0.05, lambda: self._legit_packet(self.newcomers, 0.05))
        for a in self.active(t):
            rate = self._rate(a, t) * (1 + r.gauss(0, cfg.noise / 2))
            if a.kind == "flash_crowd":  # a real rush of new players: legit, handshakes complete
                samples += self._class(rate, lambda: self._legit_packet(self.newcomers, 0.05), cfg.attack_samples)
            else:
                samples += self._class(rate, lambda k=a.kind: self._attack_packet(k), cfg.attack_samples)
        return samples


class SimDataPlane:
    """Upstream filter -> link -> XDP (count, then drop on rule) -> server capacity."""

    def __init__(self, sim: TrafficSim, allowlist: list[str]):
        self.sim = sim
        nets = [ipaddress.IPv4Network(n) for n in allowlist]
        self.allow = [(int(n.network_address), int(n.netmask)) for n in nets]
        self.trusted: set[int] = set()
        self.rules: list[Rule] = []
        self.upstream: list[Rule] = []

    def _allowed(self, src: int) -> bool:
        return any(src & mask == net for net, mask in self.allow)

    def _apply(self, samples: list[Packet], rules: list[Rule], hits: dict[int, float]) -> list[Packet]:
        if not rules:
            return samples
        # pass 1: how much traffic matches each rate-limit rule (sets token-bucket pass rate)
        match_w = {r.id: 0.0 for r in rules}
        for p in samples:
            if self._allowed(p.src):
                continue
            for r in rules:
                if r.matches(p, self.trusted):
                    match_w[r.id] += p.w
                    break
        keep_frac = {r.id: (0.0 if r.action == "drop" else min(1.0, r.rate_pps / match_w[r.id]) if match_w[r.id] else 1.0)
                     for r in rules}
        out = []
        for p in samples:
            rule = None
            if not self._allowed(p.src):
                rule = next((r for r in rules if r.matches(p, self.trusted)), None)
            if rule is None:
                out.append(p)
                continue
            kf = keep_frac[rule.id]
            hits[rule.id] = hits.get(rule.id, 0.0) + p.w * (1 - kf)
            if kf > 0:
                q = Packet(p.src, p.sport, p.dport, p.proto, p.flags, p.size, p.w * kf, p.legit)
                out.append(q)
        return out

    def tick(self, t: int) -> tuple[Window, TickResult]:
        cfg = self.sim.cfg
        res = TickResult()
        offered = self.sim.offered(t)
        res.offered_legit = sum(p.w for p in offered if p.legit)
        res.offered_attack = sum(p.w for p in offered if not p.legit)

        # Upstream (ISP) FlowSpec filters run before our link.
        after_up = self._apply(offered, self.upstream, res.upstream_hits)

        # The link: anything beyond its capacity is lost before reaching us.
        bps = sum(p.w * p.size * 8 for p in after_up)
        link_frac = min(1.0, cfg.link_bps / bps) if bps else 1.0
        arriving = [Packet(p.src, p.sport, p.dport, p.proto, p.flags, p.size, p.w * link_frac, p.legit)
                    for p in after_up]
        res.legit_after_link = sum(p.w for p in arriving if p.legit)

        # XDP: counters see everything that arrives (count first) ...
        window = Window(t=t, samples=arriving)
        # ... then rules drop what matches.
        passed = self._apply(arriving, self.rules, res.rule_hits)
        res.passed_legit = sum(p.w for p in passed if p.legit)
        res.passed_attack = sum(p.w for p in passed if not p.legit)
        res.dropped = sum(p.w for p in arriving) - res.passed_legit - res.passed_attack

        # The protected server can only process so many packets per second.
        total = res.passed_legit + res.passed_attack
        served_frac = min(1.0, cfg.server_capacity_pps / total) if total else 1.0
        res.served_legit = res.passed_legit * served_frac

        window.truth = {
            "legit_pps": res.offered_legit,
            "attack_pps": res.offered_attack,
            "passed_pps": total,
            "served_pct": res.legit_served_pct,
            "link_util": min(1.0, bps / cfg.link_bps),
        }
        return window, res
