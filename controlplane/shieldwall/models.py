"""Shared data types passed between the data plane, detector and controller."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

TCP, UDP = 6, 17
SYN, ACK = 0x02, 0x10

# Well-known reflection/amplification source ports and their attack names.
AMP_PORTS = {53: "DNS", 123: "NTP", 389: "CLDAP", 1900: "SSDP", 11211: "Memcached", 19: "Chargen"}


def ip_str(addr: int) -> str:
    return str(ipaddress.IPv4Address(addr))


def ip_int(addr: str) -> int:
    return int(ipaddress.IPv4Address(addr))


@dataclass(slots=True)
class Packet:
    """One sampled packet. `w` is how many real packets this sample stands for."""
    src: int
    sport: int
    dport: int
    proto: int
    flags: int
    size: int
    w: float = 1.0
    legit: bool = True  # ground truth, only known inside the simulator


@dataclass
class Window:
    """Everything the data plane saw in one control-loop window (1 s)."""
    t: int
    samples: list[Packet]
    truth: dict = field(default_factory=dict)  # simulator-only ground truth


@dataclass
class Features:
    t: int
    pps: float
    bps: float
    syn_pps: float
    ack_pps: float
    udp_share: float
    syn_ack_ratio: float
    amp_share: float
    amp_port: int | None
    unique_sources: int
    new_source_share: float
    src_entropy: float
    dport_entropy: float
    top_talkers: list[tuple[str, float]]


@dataclass
class Verdict:
    t: int
    anomalous: bool          # methods agree AND persistence + floor guards pass
    votes: dict[str, bool]   # which of zscore / cusum / entropy fired
    zscore: float
    cusum: float
    entropy_z: float
    baseline_pps: float


@dataclass
class Rule:
    """A data-plane rule. Mirrors `struct rule_key/rule_val` in bpf/xdp_filter.c."""
    id: int
    action: str              # "drop" | "rate_limit"
    proto: int
    sport: int = 0           # 0 = any
    dport: int = 0
    syn_only: bool = False
    untrusted_only: bool = False
    rate_pps: float = 0.0
    expires_at: int = 0
    reason: str = ""
    mode: str = "enforce"    # "enforce" | "dry-run"
    hits: float = 0.0

    def matches(self, p: Packet, trusted: set[int]) -> bool:
        if p.proto != self.proto:
            return False
        if self.sport and p.sport != self.sport:
            return False
        if self.dport and p.dport != self.dport:
            return False
        if self.syn_only and not (p.flags & SYN and not p.flags & ACK):
            return False
        if self.untrusted_only and p.src in trusted:
            return False
        return True

    def describe(self) -> str:
        proto = {TCP: "TCP", UDP: "UDP"}.get(self.proto, str(self.proto))
        parts = [proto]
        if self.sport:
            parts.append(f"src port {self.sport}")
        if self.dport:
            parts.append(f"dst port {self.dport}")
        if self.syn_only:
            parts.append("SYN only")
        if self.untrusted_only:
            parts.append("from unknown sources")
        what = " ".join(parts)
        if self.action == "drop":
            return f"DROP {what}"
        return f"RATE-LIMIT {what} to {self.rate_pps:,.0f} pps"
