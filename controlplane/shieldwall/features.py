"""Step 1 of the control loop: turn raw per-window counts into features."""
from __future__ import annotations

import math
from collections import defaultdict

from .models import ACK, AMP_PORTS, SYN, UDP, Features, Window, ip_str
from .sketches import BloomFilter, CountMinSketch, HyperLogLog


def entropy(weights) -> float:
    """Shannon entropy H = -sum(p_i * log2 p_i) of a weight distribution."""
    total = sum(weights)
    if total <= 0:
        return 0.0
    h = 0.0
    for w in weights:
        if w > 0:
            p = w / total
            h -= p * math.log2(p)
    return h


class Featurizer:
    def __init__(self):
        # Long-lived memory of sources seen during calm traffic.
        self.seen = BloomFilter(n=200_000, fp_rate=0.01)

    def featurize(self, win: Window) -> Features:
        pps = bps = syn = ack = udp = amp = 0.0
        amp_by_port: dict[int, float] = defaultdict(float)
        by_src: dict[int, float] = defaultdict(float)
        by_dport: dict[int, float] = defaultdict(float)
        new_w = 0.0
        hll = HyperLogLog()
        cms = CountMinSketch(top_k=5)

        for p in win.samples:
            w = p.w
            pps += w
            bps += w * p.size * 8
            if p.proto == UDP:
                udp += w
                if p.sport in AMP_PORTS:
                    amp += w
                    amp_by_port[p.sport] += w
            elif p.flags & SYN and not p.flags & ACK:
                syn += w
            elif p.flags & ACK:
                ack += w
            by_src[p.src] += w
            by_dport[p.dport] += w

        for src, w in by_src.items():
            hll.add(src)
            cms.add(src, w)
            if src not in self.seen:
                new_w += w

        amp_port = max(amp_by_port, key=amp_by_port.get) if amp_by_port else None
        return Features(
            t=win.t,
            pps=pps,
            bps=bps,
            syn_pps=syn,
            ack_pps=ack,
            udp_share=udp / pps if pps else 0.0,
            syn_ack_ratio=syn / max(ack, 1.0),
            amp_share=amp / pps if pps else 0.0,
            amp_port=amp_port,
            unique_sources=hll.count(),
            new_source_share=new_w / pps if pps else 0.0,
            src_entropy=entropy(by_src.values()),
            dport_entropy=entropy(by_dport.values()),
            top_talkers=[(ip_str(k), v) for k, v in cms.top(5)],
        )

    def learn(self, win: Window) -> None:
        """Remember sources only from calm windows, so an attack can't poison 'normal'."""
        for src in {p.src for p in win.samples}:
            self.seen.add(src)
