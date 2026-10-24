"""Classify an anomaly by its fingerprint. Each attack type leaves a tell-tale signature.

| Attack              | Fingerprint we look for                                    |
|---------------------|------------------------------------------------------------|
| Amplification       | UDP arriving FROM a service port we never use (53, 389...) |
| SYN flood           | many SYNs, few ACKs (handshakes never complete)            |
| UDP flood           | UDP share jumps, mostly never-seen sources, spread ports   |
| Legit surge         | volume up, but handshakes complete and the mix looks normal|

Telling a real surge of players apart from an attack is the hard part: blocking
your own users is as much a failure as missing an attack.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import AMP_PORTS, Features


@dataclass
class Classification:
    kind: str          # e.g. "cldap_amplification", "syn_flood", "legit_surge"
    label: str         # human-readable
    malicious: bool
    confidence: float
    evidence: list[str]


class Classifier:
    def __init__(self):
        self.base_udp_share: float | None = None

    def learn(self, f: Features) -> None:
        a = 0.1
        self.base_udp_share = f.udp_share if self.base_udp_share is None else (
            (1 - a) * self.base_udp_share + a * f.udp_share)

    def classify(self, f: Features) -> Classification:
        base_udp = self.base_udp_share or 0.0

        if f.amp_share > 0.5 and f.amp_port in AMP_PORTS:
            name = AMP_PORTS[f.amp_port]
            return Classification(
                kind=f"{name.lower()}_amplification",
                label=f"{name} amplification flood",
                malicious=True,
                confidence=min(0.99, 0.6 + f.amp_share * 0.4),
                evidence=[
                    f"{f.amp_share:.0%} of traffic is UDP from source port {f.amp_port} ({name})",
                    "this server never sends " + name + " queries, so these are reflected replies",
                    f"~{f.unique_sources:,} distinct reflector sources",
                ],
            )

        if f.syn_ack_ratio > 1.0 and f.syn_pps > 1000:
            return Classification(
                kind="syn_flood",
                label="TCP SYN flood",
                malicious=True,
                confidence=min(0.99, 0.5 + f.syn_ack_ratio / 40),
                evidence=[
                    f"SYN:ACK ratio is {f.syn_ack_ratio:.1f} (normal is well under 1)",
                    f"{f.syn_pps:,.0f} connection attempts/s that never complete the handshake",
                    f"{f.new_source_share:.0%} of packets come from never-seen sources",
                ],
            )

        if f.udp_share > base_udp + 0.3 and f.new_source_share > 0.8:
            return Classification(
                kind="udp_flood",
                label="UDP flood",
                malicious=True,
                confidence=min(0.95, 0.4 + f.new_source_share * 0.5),
                evidence=[
                    f"UDP share jumped to {f.udp_share:.0%} (baseline {base_udp:.0%})",
                    f"{f.new_source_share:.0%} of packets come from never-seen sources",
                    f"destination-port entropy {f.dport_entropy:.1f} bits: ports are being sprayed",
                ],
            )

        handshakes_ok = f.syn_ack_ratio < 1.0
        mix_ok = abs(f.udp_share - base_udp) < 0.15
        if handshakes_ok and mix_ok and f.new_source_share < 0.8:
            return Classification(
                kind="legit_surge",
                label="legitimate traffic surge",
                malicious=False,
                confidence=0.8,
                evidence=[
                    f"handshakes complete normally (SYN:ACK {f.syn_ack_ratio:.2f})",
                    f"protocol mix unchanged (UDP {f.udp_share:.0%} vs {base_udp:.0%} baseline)",
                    f"only {f.new_source_share:.0%} of packets from never-seen sources",
                ],
            )

        return Classification(
            kind="unknown",
            label="unclassified anomaly",
            malicious=False,
            confidence=0.4,
            evidence=["volume is anomalous but no known fingerprint matches; observing"],
        )
