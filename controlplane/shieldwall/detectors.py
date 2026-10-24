"""Step 2 of the control loop: three statistical methods vote. No fixed thresholds.

1. EWMA baseline + z-score   z = (x - mu) / sigma
2. CUSUM                     S_t = max(0, S_{t-1} + (x_t - mu)/sigma - k)
3. Entropy swing             z-score of source-IP entropy against its own baseline

Two guards against false alarms: the vote must persist for several windows, and
the rise must clear an absolute floor (a 3 a.m. blip from 10 to 30 pps never fires).
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from .models import Features, Verdict


class EWMA:
    """Adaptive running mean and variance that lean on recent data."""

    def __init__(self, alpha: float = 0.1):
        self.alpha = alpha
        self.mean: float | None = None
        self.var = 0.0
        self.n = 0

    def update(self, x: float) -> None:
        self.n += 1
        if self.mean is None:
            self.mean = x
            return
        diff = x - self.mean
        self.mean += self.alpha * diff
        self.var = (1 - self.alpha) * (self.var + self.alpha * diff * diff)

    @property
    def std(self) -> float:
        return math.sqrt(self.var)

    def z(self, x: float, min_std: float) -> float:
        if self.mean is None:
            return 0.0
        return (x - self.mean) / max(self.std, min_std)


@dataclass
class DetectorConfig:
    warmup: int = 10            # windows of learning before we judge anything
    z_threshold: float = 6.0
    cusum_k: float = 0.5        # slack: ignore drifts smaller than k sigma
    cusum_h: float = 10.0       # alarm level for the cumulative sum
    entropy_z: float = 4.0
    persistence: int = 2        # consecutive anomalous windows before alerting
    clear_after: int = 3        # consecutive calm windows before the alert clears
    floor_pps: float = 1000.0   # absolute rise above baseline required to alert
    min_std_frac: float = 0.05  # sigma never below 5% of the mean (avoids divide-by-tiny)


class Detector:
    def __init__(self, cfg: DetectorConfig | None = None):
        self.cfg = cfg or DetectorConfig()
        self.pps = EWMA()
        self.ent = EWMA()
        self.cusum = 0.0
        self.streak = 0
        self.calm = 0
        self.in_alert = False

    def update(self, f: Features) -> Verdict:
        c = self.cfg
        warm = self.pps.n >= c.warmup
        mu = self.pps.mean if self.pps.mean is not None else f.pps
        min_std = max(1.0, (mu or 1.0) * c.min_std_frac)
        z = self.pps.z(f.pps, min_std) if warm else 0.0
        ez = self.ent.z(f.src_entropy, 0.05) if warm else 0.0

        if warm:
            self.cusum = max(0.0, self.cusum + z - c.cusum_k)
        votes = {
            "zscore": warm and z > c.z_threshold,
            "cusum": warm and self.cusum > c.cusum_h,
            "entropy": warm and abs(ez) > c.entropy_z,
        }
        agree = sum(votes.values()) >= 2
        above_floor = f.pps - mu > c.floor_pps

        if agree and above_floor:
            self.streak += 1
            self.calm = 0
        else:
            self.streak = 0
            self.calm += 1

        if not self.in_alert and self.streak >= c.persistence:
            self.in_alert = True
        elif self.in_alert and self.calm >= c.clear_after:
            self.in_alert = False
            self.cusum = 0.0

        # Freeze the baseline while anything looks off, so an attack never becomes "normal".
        # (A confirmed legitimate surge is adopted explicitly through rebaseline().)
        if not self.in_alert and not agree:
            self.pps.update(f.pps)
            self.ent.update(f.src_entropy)

        return Verdict(
            t=f.t,
            anomalous=self.in_alert,
            votes=votes,
            zscore=z,
            cusum=self.cusum,
            entropy_z=ez,
            baseline_pps=mu,
        )

    def rebaseline(self, f: Features) -> None:
        """Adopt the current level as the new normal (called after a sustained legitimate surge)."""
        self.pps.mean = f.pps
        self.pps.var = (self.cfg.min_std_frac * f.pps) ** 2
        self.ent.mean = f.src_entropy
        self.ent.var = 0.05 ** 2
        self.cusum = 0.0
        self.streak = 0
        self.calm = 0
        self.in_alert = False
