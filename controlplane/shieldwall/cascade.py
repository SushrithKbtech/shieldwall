"""The three-tier cascade, as one classifier the engine can use in place of the
bare fingerprints.

  Tier 1  statistics (the detector) decides THAT something is wrong -- upstream of this.
  here:
    fast path   hand-written fingerprints name a known signature          (classifier.py)
    Tier 2      a trained ML model names families with no signature yet    (ml.py)
    Tier 3      genuine anomaly nobody can name -> flagged for the LLM     (needs_llm=True)

If no ML model is present it degrades to exactly the old fingerprint behaviour, so
the base tool still runs with no extra dependencies.
"""
from __future__ import annotations

import os
import sys

from .classifier import Classification, Classifier
from .models import Features

ML_LABEL = {
    "cldap_amp": "CLDAP amplification flood", "dns_amp": "DNS amplification flood",
    "ntp_amp": "NTP amplification flood", "memcached_amp": "Memcached amplification flood",
    "ssdp_amp": "SSDP amplification flood", "syn_flood": "TCP SYN flood",
    "synack_reflection": "TCP SYN-ACK reflection flood", "udp_flood": "UDP flood",
    "single_source_flood": "single-host flood",
}
# ML family -> the controller's attack kind, so an ML-named attack gets the same rules as a fingerprinted one
ML_KIND = {f"{name}_amp": f"{name}_amplification" for name in ("cldap", "dns", "ntp", "memcached", "ssdp")}
_DEFAULT_MODEL = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "results", "ml_model.joblib")


class CascadeClassifier:
    def __init__(self, model_path: str | None = None, ml_threshold: float = 0.6):
        self.fp = Classifier()
        self.ml = None
        self.threshold = ml_threshold
        self.last_source = "fingerprint"
        path = model_path or os.environ.get("SHIELDWALL_ML_MODEL", _DEFAULT_MODEL)
        if path and os.path.exists(path) and os.environ.get("SHIELDWALL_ML", "on").lower() != "off":
            try:
                from .ml import MLClassifier
                self.ml = MLClassifier.load(path)
            except Exception as e:  # missing scikit-learn, or a pickle from other library versions
                self.ml = None
                print(f"shieldwall: ML tier off, could not load {path}: {e}", file=sys.stderr)

    def learn(self, f: Features) -> None:
        self.fp.learn(f)

    def classify(self, f: Features) -> Classification:
        c = self.fp.classify(f)
        # fast path: a known signature matched, or the fingerprints are confident it is
        # not an attack (e.g. a legitimate surge). Either way, trust the named verdict.
        if c.kind != "unknown":
            c.source = self.last_source = "fingerprint"
            return c
        # fingerprint could not name it -> Tier 2
        if self.ml is not None:
            mv = self.ml.predict(f)
            if mv.confidence >= self.threshold:
                self.last_source = "ml"
                if mv.malicious:
                    return Classification(
                        kind=ML_KIND.get(mv.family, mv.family), label=ML_LABEL.get(mv.family, mv.family), malicious=True,
                        confidence=mv.confidence,
                        evidence=[f"ML classifier identified {ML_LABEL.get(mv.family, mv.family)} "
                                  f"(confidence {mv.confidence:.0%})",
                                  "no hand-written signature matched this traffic"],
                        source="ml")
                # ML is confident this is normal traffic -> not an attack
                return Classification(
                    kind=mv.family, label="legitimate traffic", malicious=False, confidence=mv.confidence,
                    evidence=[f"ML classifier: normal traffic (confidence {mv.confidence:.0%})"], source="ml")
            # Tier 2 is unsure either way -> residual for the Tier 3 analyst
            self.last_source = "residual"
            c.needs_llm = True
            c.source = "residual"
            c.evidence = list(c.evidence) + [
                f"ML top guess: {ML_LABEL.get(mv.family, mv.family)} at {mv.confidence:.0%} "
                f"(below the {self.threshold:.0%} bar), so escalated to the analyst"]
            return c
        # no model: behave exactly like the old fingerprints
        c.source = self.last_source = "fingerprint"
        return c
