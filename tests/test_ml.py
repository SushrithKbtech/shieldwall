import math
import os

import pytest

os.environ.setdefault("SHIELDWALL_LLM", "template")

from shieldwall.analyst import _heuristic, investigate
from shieldwall.cascade import CascadeClassifier
from shieldwall.engine import Engine
from shieldwall.features import Featurizer
from shieldwall.mitigation import MitigationController, suggestion_to_rule
from shieldwall.ml import FEATURE_NAMES, MLVerdict, feat_vector
from shieldwall.models import ACK, SYN, TCP, Features, Packet, Window


def feats(**kw) -> Features:
    base = dict(t=0, pps=50_000.0, bps=2e7, syn_pps=0.0, ack_pps=48_000.0, udp_share=0.05, syn_ack_ratio=0.0,
                amp_share=0.0, amp_port=None, unique_sources=5_000, new_source_share=0.95, src_entropy=12.0,
                dport_entropy=14.0, top_talkers=[])
    base.update(kw)
    return Features(**base)


class StubML:
    """Stands in for the trained model so routing can be tested without scikit-learn."""

    def __init__(self, family, confidence):
        self.verdict = MLVerdict(family, confidence, family not in ("benign", "legit_surge"), {family: confidence})

    def predict(self, f):
        return self.verdict


def cascade(ml=None) -> CascadeClassifier:
    c = CascadeClassifier(model_path=os.devnull)
    c.ml = ml
    return c


def test_feature_vector_matches_names_and_never_has_nan():
    # the live kernel path cannot measure destination-port entropy (NaN); the model must not depend on it
    v = feat_vector(feats(dport_entropy=math.nan, synack_pps=30_000.0))
    assert len(v) == len(FEATURE_NAMES)
    assert not any(math.isnan(x) for x in v)
    assert v[FEATURE_NAMES.index("synack_share")] == pytest.approx(0.6)


def test_featurizer_counts_synack_separately_from_syn():
    pkts = [Packet(1, 443, 5000, TCP, SYN | ACK, 60), Packet(2, 5000, 25565, TCP, SYN, 60),
            Packet(3, 5000, 25565, TCP, ACK, 60)]
    f = Featurizer().featurize(Window(t=0, samples=pkts))
    assert (f.syn_pps, f.ack_pps, f.synack_pps) == (1, 2, 1)


def test_known_signature_takes_the_fast_path():
    c = cascade(StubML("synack_reflection", 0.99)).classify(feats(udp_share=1.0, amp_share=0.9, amp_port=389))
    assert c.kind == "cldap_amplification" and c.source == "fingerprint"


def test_ml_names_what_no_fingerprint_matches_and_maps_to_a_rule():
    c = cascade(StubML("synack_reflection", 0.97)).classify(feats())
    assert (c.kind, c.malicious, c.source, c.needs_llm) == ("synack_reflection", True, "ml", False)
    rules = MitigationController()._rules_for(c, feats(), 2_000, 0)
    assert len(rules) == 1 and rules[0].synack_only and rules[0].untrusted_only
    syn_ack = Packet(9, 443, 40000, TCP, SYN | ACK, 60)
    new_player = Packet(9, 40000, 25565, TCP, SYN, 60)
    assert rules[0].matches(syn_ack, set()) and not rules[0].matches(new_player, set())


def test_ml_amplification_names_use_the_signature_rules():
    # too small a share for the fingerprint (needs > 50%), so only the model names it
    c = cascade(StubML("cldap_amp", 0.9)).classify(feats(udp_share=0.4, amp_share=0.4, amp_port=389,
                                                         amp_ports_seen=[389], new_source_share=0.5))
    assert c.kind == "cldap_amplification" and c.source == "ml"
    rules = MitigationController()._rules_for(c, feats(amp_port=389, amp_ports_seen=[389]), 2_000, 0)
    assert any(r.sport == 389 and r.action == "drop" for r in rules)


def test_confident_benign_is_not_an_attack():
    c = cascade(StubML("benign", 0.95)).classify(feats())
    assert not c.malicious and c.source == "ml"


def test_unsure_model_escalates_to_the_analyst():
    c = cascade(StubML("udp_flood", 0.4)).classify(feats())
    assert c.needs_llm and c.source == "residual" and not c.malicious


def test_without_a_model_it_behaves_like_the_fingerprints():
    c = cascade(None).classify(feats())
    assert c.kind == "unknown" and c.source == "fingerprint" and not c.needs_llm


@pytest.mark.parametrize("profile, expect", [
    ({"top_talkers": [{"ip": "203.0.113.9", "share": 0.6}]}, dict(source_ip="203.0.113.9", action="drop")),
    ({"udp_share": 0.9, "top_source_ports": [{"port": 161, "share": 0.9}]}, dict(src_port=161, protocol="udp")),
    ({"synack_share": 0.8}, dict(synack_only=True, action="rate_limit")),
    ({"syn_to_ack_ratio": 5.0}, dict(syn_only=True, action="rate_limit")),
    ({}, dict(unknown_sources_only=True, action="rate_limit")),
])
def test_analyst_heuristic_proposes_a_valid_narrow_rule(profile, expect):
    s = _heuristic(profile)
    assert all(s[k] == v for k, v in expect.items())
    suggestion_to_rule(s)  # every proposal must be a rule the controller can build


def test_analyst_prefers_the_reflected_port_over_blocking_a_public_resolver():
    # real DNS capture: the biggest "sender" is 8.8.8.8, which the server itself may rely on
    s = _heuristic({"udp_share": 0.95, "top_talkers": [{"ip": "8.8.8.8", "share": 0.45}],
                    "top_source_ports": [{"port": 53, "protocol": "udp", "share": 0.7}]})
    assert s["src_port"] == 53 and s["source_ip"] is None


def test_null_written_as_text_means_not_set():
    # gpt-4o-mini sometimes writes "null" as a string; that must not reject an otherwise good rule
    r = suggestion_to_rule({"action": "rate_limit", "protocol": "tcp", "source_ip": "null", "src_port": "null",
                            "dst_port": None, "synack_only": True, "unknown_sources_only": True, "rate_pps": 100})
    assert (r.src_mask, r.sport, r.dport, r.synack_only) == (0, 0, 0, True)


def test_analyst_never_proposes_dropping_the_game_ports():
    s = _heuristic({"udp_share": 0.9, "top_source_ports": [{"port": 19132, "share": 0.9}]})
    assert s.get("src_port") != 19132


def test_analyst_rule_is_validated_and_only_dry_run():
    eng = Engine(explain_async=False)
    eng.classifier = cascade(StubML("udp_flood", 0.3))  # nobody can name it: the residual path
    eng.launch("synack", duration=20, start=30)
    for _ in range(36):
        eng.step()
    events = eng.store.query("SELECT detail FROM events WHERE kind = 'analyst'")
    assert events and events[0]["detail"].startswith("accepted (dry-run)")
    assert "SYN-ACK only" in events[0]["detail"]
    added = [r for r in eng.controller.rules.values() if r.reason.startswith("suggested by LLM")]
    assert added and all(r.mode == "dry-run" for r in added)
    assert investigate(eng)["verdict"]["accepted"] is False  # a second identical proposal is a duplicate


def test_trained_model_blocks_synack_reflection_end_to_end():
    pytest.importorskip("sklearn")
    from shieldwall.ml_train import build_dataset, train

    X, _, y, _ = build_dataset(per_attack=25, benign=60, surge=40, seed0=50_000)
    eng = Engine(explain_async=False)
    eng.classifier = cascade(train(X, y))
    eng.launch("synack", duration=20, start=30)
    pts = [eng.step() for _ in range(55)]
    inc = eng.store.incidents(5)[0]
    assert inc["kind"] == "synack_reflection" and inc["malicious"]
    assert inc["mitigate_s"] is not None and inc["mitigate_s"] <= 4
    blocked = [p for p in pts if 36 <= p["t"] < 50]
    assert sum(p["attack_passed"] for p in blocked) < 0.01 * sum(p["attack_arrived"] for p in blocked)
    assert min(p["served_pct"] for p in blocked) > 99
