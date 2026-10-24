import os

from shieldwall.detectors import EWMA, Detector
from shieldwall.engine import Engine
from shieldwall.features import entropy
from shieldwall.mitigation import MitigationConfig
from shieldwall.models import Features

os.environ.setdefault("SHIELDWALL_LLM", "template")


def feats(t, pps, ent=8.0):
    return Features(t=t, pps=pps, bps=pps * 4000, syn_pps=0, ack_pps=pps, udp_share=0.2, syn_ack_ratio=0.01,
                    amp_share=0, amp_port=None, unique_sources=300, new_source_share=0.05, src_entropy=ent,
                    dport_entropy=1, top_talkers=[])


def test_entropy_bounds():
    assert entropy([1, 1, 1, 1]) == 2.0
    assert entropy([5]) == 0.0


def test_ewma_tracks_mean():
    e = EWMA(alpha=0.2)
    for _ in range(100):
        e.update(1000)
    assert abs(e.mean - 1000) < 1e-6
    assert e.z(5000, 50) > 10


def test_detector_ignores_small_night_blip():
    d = Detector()
    for t in range(30):
        d.update(feats(t, 10 + (t % 3)))
    for t in range(30, 40):
        v = d.update(feats(t, 30))  # 3x jump, but tiny in absolute terms
    assert not v.anomalous


def test_detector_needs_persistence():
    d = Detector()
    for t in range(30):
        d.update(feats(t, 2000 + (t % 5) * 20))
    v1 = d.update(feats(30, 200_000, ent=11))
    v2 = d.update(feats(31, 200_000, ent=11))
    assert not v1.anomalous and v2.anomalous


def _run(preset, dry_run=False):
    eng = Engine(mit_cfg=MitigationConfig(dry_run=dry_run), explain_async=False)
    eng.launch(preset, duration=30, start=30)
    points = [eng.step() for _ in range(70)]
    return eng, points


def test_cldap_amplification_detected_and_dropped():
    eng, pts = _run("cldap")
    inc = eng.store.incidents(1)[0]
    assert inc["kind"] == "cldap_amplification"
    assert any("DROP UDP src port 389" in e["detail"] for e in eng.store.recent_events(50))
    during = [p for p in pts if 35 <= p["t"] < 60]
    assert min(p["served_pct"] for p in during) > 95


def test_syn_flood_rate_limited():
    eng, pts = _run("syn")
    assert eng.store.incidents(1)[0]["kind"] == "syn_flood"
    assert min(p["served_pct"] for p in pts if 35 <= p["t"] < 60) > 90


def test_flash_crowd_is_not_blocked():
    eng, pts = _run("flash_crowd")
    assert not eng.store.query("SELECT id FROM events WHERE kind = 'rule_added'")
    assert all(p["served_pct"] > 99 for p in pts)


def test_dry_run_never_drops():
    eng, pts = _run("cldap", dry_run=True)
    assert all(p["passed_pps"] >= p["pps"] - 1 for p in pts)


def test_rules_expire_after_attack():
    eng = Engine(explain_async=False)
    eng.launch("cldap", duration=10, start=30)
    for _ in range(130):
        eng.step()
    assert not eng.controller.rules
    assert eng.store.query("SELECT id FROM events WHERE kind = 'rule_expired'")


def test_sustained_legit_surge_becomes_new_normal_and_attacks_still_caught():
    from shieldwall.simulator import AttackSpec
    eng = Engine(explain_async=False)
    eng.sim.add_attack(AttackSpec(kind="flash_crowd", start=30, end=None, pps=6_000, ramp=8))
    eng.launch("cldap", duration=20, start=120)
    pts = [eng.step() for _ in range(150)]
    assert eng.store.query("SELECT id FROM events WHERE kind = 'rebaselined'")
    assert not any(p["anomalous"] for p in pts if 80 <= p["t"] < 120)   # surge accepted as normal
    assert pts[110]["baseline"] > 6_000
    assert any(p["malicious_alert"] for p in pts if 120 <= p["t"] < 125)  # attack on top still caught
    assert min(p["served_pct"] for p in pts if 124 <= p["t"] < 140) > 95
