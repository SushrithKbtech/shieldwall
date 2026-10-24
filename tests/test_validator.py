import os

from shieldwall.engine import Engine
from shieldwall.mitigation import validate_suggestion

os.environ.setdefault("SHIELDWALL_LLM", "template")


def rule(**kw):
    base = {"action": "drop", "protocol": "udp", "src_port": None, "dst_port": None, "syn_only": False,
            "fragments_only": False, "unknown_sources_only": False, "rate_pps": None, "reason": "test"}
    return {**base, **kw}


def cldap_engine():
    eng = Engine(explain_async=False)
    eng.launch("cldap", duration=30, start=40)
    for _ in range(55):
        eng.step()
    return eng


def check(eng, s):
    return validate_suggestion(s, eng.controller, eng.attack_sample, eng.calm_sample, set(eng.trusted), eng.t)


def test_rejects_too_broad():
    assert "too broad" in check(cldap_engine(), rule())["verdict"]


def test_rejects_duplicate_of_existing_rule():
    assert "already in place" in check(cldap_engine(), rule(src_port=389))["verdict"]


def test_rejects_rule_that_would_block_players():
    out = check(cldap_engine(), rule(action="rate_limit", protocol="tcp", dst_port=25565, rate_pps=10))
    assert not out["accepted"] and "normal player traffic" in out["verdict"]


def test_rejects_rule_that_misses_the_attack():
    out = check(cldap_engine(), rule(src_port=53))
    assert not out["accepted"] and "of the attack traffic" in out["verdict"]


def test_rejects_malformed():
    assert not check(cldap_engine(), rule(protocol="icmp"))["accepted"]
    assert not check(cldap_engine(), rule(action="rate_limit", src_port=389, rate_pps=None))["accepted"]


def test_accepts_safe_relevant_rule_in_dry_run_only():
    eng = cldap_engine()
    out = check(eng, rule(unknown_sources_only=True))
    assert out["accepted"] and "dry-run" in out["verdict"]
    added = [r for r in eng.controller.rules.values() if r.reason.startswith("suggested by LLM")]
    assert added and all(r.mode == "dry-run" for r in added)
    assert all(r.mode == "enforce" for r in eng.controller.enforced_rules())  # never enforced automatically


def test_rejects_drop_on_the_game_port_even_for_unknown_sources():
    out = check(cldap_engine(), rule(protocol="tcp", dst_port=25565, syn_only=True, unknown_sources_only=True))
    assert not out["accepted"] and "lock out new players" in out["verdict"]
