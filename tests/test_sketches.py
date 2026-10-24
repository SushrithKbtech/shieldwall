import random

from shieldwall.sketches import BloomFilter, CountMinSketch, HyperLogLog


def test_count_min_never_undercounts_and_finds_top_talker():
    cms = CountMinSketch(width=512, depth=4, top_k=3)
    rng = random.Random(1)
    truth = {}
    for _ in range(5000):
        k = rng.randint(1, 2000)
        truth[k] = truth.get(k, 0) + 1
        cms.add(k)
    for _ in range(3000):  # one heavy hitter
        cms.add(42)
    truth[42] = truth.get(42, 0) + 3000
    for k, n in truth.items():
        assert cms.estimate(k) >= n
    assert cms.top(1)[0][0] == 42


def test_hyperloglog_within_a_few_percent():
    hll = HyperLogLog(p=10)
    for i in range(20_000):
        hll.add(i * 7919)
    assert abs(hll.count() - 20_000) / 20_000 < 0.08
    assert hll.memory_bytes <= 1024


def test_bloom_no_false_negatives_low_false_positives():
    bf = BloomFilter(n=10_000, fp_rate=0.01)
    for i in range(10_000):
        bf.add(i)
    assert all(i in bf for i in range(10_000))
    fp = sum((i in bf) for i in range(1_000_000, 1_010_000))
    assert fp / 10_000 < 0.03
