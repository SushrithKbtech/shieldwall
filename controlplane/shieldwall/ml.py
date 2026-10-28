"""Tier 2: a trained ML classifier over the SAME per-window features the engine
already computes (features.py). It names the attack family and returns a
confidence. A low confidence, or a family the model is unsure about, is what the
engine escalates to the Tier 3 LLM analyst.

Dependency-light: scikit-learn + numpy are needed only to train or load a model.
With no model present the engine falls back to the hand-written fingerprints
(classifier.py), so the base tool still runs anywhere.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from .models import Features

# The numeric feature vector. Deliberately mostly scale-invariant (shares, ratios,
# entropy) so the model learns attack *shape*, not just "lots of packets". Only
# features the real kernel maps also provide: the XDP program does not count
# destination ports, so destination-port entropy is left out.
FEATURE_NAMES = [
    "log_pps", "log_bps", "udp_share", "log_syn_ack", "amp_share", "frag_share",
    "new_source_share", "src_entropy", "synack_share", "top_share",
    "log_unique", "syn_share", "ack_share", "n_amp_ports",
    "avg_bytes_log",            # mean packet size: NTP replies are small, DNS/CLDAP large
    "amp53", "amp123", "amp389", "amp1900", "amp11211",  # which reflection port is present
]

_AMP_PORTS_FEAT = (53, 123, 389, 1900, 11211)

# Human-readable label -> whether it is an attack.
BENIGN_LABELS = {"benign", "legit_surge"}


def feat_vector(f: Features) -> list[float]:
    pps = f.pps or 0.0
    return [
        math.log1p(max(0.0, f.pps)),
        math.log1p(max(0.0, f.bps)),
        f.udp_share,
        math.log1p(max(0.0, f.syn_ack_ratio)),
        f.amp_share,
        f.frag_share,
        f.new_source_share,
        f.src_entropy,
        (f.synack_pps / pps) if pps else 0.0,
        f.top_share,
        math.log1p(max(0, f.unique_sources)),
        (f.syn_pps / pps) if pps else 0.0,
        (f.ack_pps / pps) if pps else 0.0,
        float(len(f.amp_ports_seen)),
        math.log1p((f.bps / (8.0 * pps)) if pps else 0.0),
        *(1.0 if p in f.amp_ports_seen else 0.0 for p in _AMP_PORTS_FEAT),
    ]


@dataclass
class MLVerdict:
    family: str          # e.g. "cldap_amp", "synack_reflection", "benign"
    confidence: float    # max class probability, 0..1
    malicious: bool
    proba: dict          # full probability per class


class MLClassifier:
    """Thin wrapper around a scikit-learn probabilistic classifier."""

    def __init__(self, model=None, labels=None):
        self.model = model
        self.labels = labels or []

    @classmethod
    def load(cls, path: str) -> "MLClassifier":
        import joblib
        blob = joblib.load(path)
        return cls(blob["model"], blob["labels"])

    def save(self, path: str) -> None:
        import joblib
        joblib.dump({"model": self.model, "labels": self.labels}, path)

    def predict(self, f: Features) -> MLVerdict:
        import numpy as np
        x = np.asarray([feat_vector(f)], dtype=float)
        proba = self.model.predict_proba(x)[0]
        i = int(proba.argmax())
        family = str(self.model.classes_[i])
        return MLVerdict(
            family=family,
            confidence=float(proba[i]),
            malicious=family not in BENIGN_LABELS,
            proba={str(c): float(p) for c, p in zip(self.model.classes_, proba)},
        )
