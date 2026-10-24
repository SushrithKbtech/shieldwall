"""Probabilistic data structures: track millions of sources in kilobytes.

Count-Min Sketch  -> who are the top talkers?
HyperLogLog       -> how many unique sources?
Bloom filter      -> have I seen this source before?

All three hash plain integers (IPv4 addresses) with a fast 64-bit mixer so the
per-packet cost stays tiny and results are deterministic across runs.
"""
from __future__ import annotations

import heapq
import math

_MASK64 = (1 << 64) - 1


def mix64(x: int, seed: int = 0) -> int:
    """splitmix64 finaliser: a cheap, well-distributed 64-bit hash for ints."""
    x = (x + 0x9E3779B97F4A7C15 + seed * 0xBF58476D1CE4E5B9) & _MASK64
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & _MASK64
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & _MASK64
    return x ^ (x >> 31)


class CountMinSketch:
    """depth x width grid of counters. Overcounts slightly, never undercounts."""

    def __init__(self, width: int = 2048, depth: int = 4, top_k: int = 10):
        self.width, self.depth, self.top_k = width, depth, top_k
        self.rows = [[0.0] * width for _ in range(depth)]
        self.candidates: dict[int, float] = {}

    def add(self, key: int, count: float = 1.0) -> None:
        est = math.inf
        for d in range(self.depth):
            i = mix64(key, d) % self.width
            self.rows[d][i] += count
            est = min(est, self.rows[d][i])
        # keep a small candidate set of heavy hitters for top-k queries
        if key in self.candidates or len(self.candidates) < self.top_k * 8:
            self.candidates[key] = est
        else:
            low_key = min(self.candidates, key=self.candidates.__getitem__)
            if est > self.candidates[low_key]:
                del self.candidates[low_key]
                self.candidates[key] = est

    def estimate(self, key: int) -> float:
        return min(self.rows[d][mix64(key, d) % self.width] for d in range(self.depth))

    def top(self, k: int | None = None) -> list[tuple[int, float]]:
        k = k or self.top_k
        return heapq.nlargest(k, ((key, self.estimate(key)) for key in self.candidates), key=lambda kv: kv[1])

    @property
    def memory_bytes(self) -> int:
        return self.width * self.depth * 8


class HyperLogLog:
    """Distinct-count estimator. p=10 -> 1024 registers, ~3% standard error."""

    def __init__(self, p: int = 10):
        self.p = p
        self.m = 1 << p
        self.registers = bytearray(self.m)
        self.alpha = 0.7213 / (1 + 1.079 / self.m)

    def add(self, key: int) -> None:
        h = mix64(key, 99)
        idx = h >> (64 - self.p)
        rest = (h << self.p) & _MASK64
        rank = (64 - self.p) + 1 if rest == 0 else (64 - rest.bit_length()) + 1
        if rank > self.registers[idx]:
            self.registers[idx] = rank

    def count(self) -> int:
        z = sum(2.0 ** -r for r in self.registers)
        est = self.alpha * self.m * self.m / z
        zeros = self.registers.count(0)
        if est <= 2.5 * self.m and zeros:  # small-range correction
            est = self.m * math.log(self.m / zeros)
        return int(round(est))

    @property
    def memory_bytes(self) -> int:
        return self.m


class BloomFilter:
    """'Definitely not seen' or 'probably seen'. Sized for n items at fp_rate."""

    def __init__(self, n: int = 100_000, fp_rate: float = 0.01):
        self.size = max(64, int(-n * math.log(fp_rate) / (math.log(2) ** 2)))
        self.k = max(1, int(round(self.size / n * math.log(2))))
        self.bits = bytearray((self.size + 7) // 8)
        self.items = 0

    def _positions(self, key: int):
        h1, h2 = mix64(key, 7), mix64(key, 13) | 1
        for i in range(self.k):
            yield (h1 + i * h2) % self.size

    def add(self, key: int) -> None:
        for pos in self._positions(key):
            self.bits[pos >> 3] |= 1 << (pos & 7)
        self.items += 1

    def __contains__(self, key: int) -> bool:
        return all(self.bits[pos >> 3] & (1 << (pos & 7)) for pos in self._positions(key))

    @property
    def memory_bytes(self) -> int:
        return len(self.bits)
