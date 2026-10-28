"""Tier 3: the LLM analyst for residual anomalies that the statistics (Tier 1) and
the ML model (Tier 2) could not confidently name.

It investigates the structured evidence and proposes ONE narrow filter rule. The
controller then validates that rule against real traffic (mitigation.validate_suggestion)
and installs it only in dry-run. The analyst never blocks anything itself.

Backends:
  * a real LLM (OPENAI_API_KEY / ANTHROPIC_API_KEY) reasons over the evidence, OR
  * a deterministic, evidence-driven heuristic when no key is present,
so the full pipeline -- investigate -> propose -> validate -> dry-run -- is
demonstrable offline. The safety gate is identical either way.
"""
from __future__ import annotations

import json

from .llm import FIELD_GUIDE, _backend, ask_llm
from .mitigation import validate_suggestion

SERVICE_PORTS = (25565, 19132)  # the game's own ports: never propose dropping these

ANALYST_SYSTEM = (
    "You are ShieldWall's Tier 3 analyst. An anomaly fired but no statistical signature and no trained "
    "model could name it, so you must reason from the evidence. Propose exactly ONE narrow mitigation rule "
    "as JSON with these keys: action (drop|rate_limit), protocol (udp|tcp|any), source_ip (or null), "
    "src_port (or null), dst_port (or null), syn_only (bool), fragments_only (bool), "
    "unknown_sources_only (bool), rate_pps (int or null), reason (string). The controller will test your "
    "rule against real player traffic and reject it if it hits players or misses the attack, so prefer a "
    "narrow rule: a source port, fragments, SYN-only, a single heavy source, or unknown-sources-only. Never "
    "drop the game ports 25565/19132. Return only the JSON object."
)


def _prompt(evidence: list[str], profile: dict) -> str:
    return (f"{FIELD_GUIDE}\n\nThis anomaly matched no known signature.\n"
            f"Evidence: {json.dumps(evidence, default=str)}\n"
            f"Traffic at the peak (JSON): {json.dumps(profile, default=str)}\n\n"
            "Propose one rule as JSON.")


def _heuristic(profile: dict) -> dict | None:
    """Evidence -> one candidate rule, used when no LLM backend is available."""
    base = {"action": "drop", "protocol": "any", "source_ip": None, "src_port": None, "dst_port": None,
            "syn_only": False, "fragments_only": False, "unknown_sources_only": False, "rate_pps": None,
            "reason": "analyst heuristic"}
    udp_share = profile.get("udp_share", 0.0)
    tt = profile.get("top_talkers") or []
    tsp = profile.get("top_source_ports") or []

    # 1. one source dominates -> drop that address
    if tt and tt[0].get("share", 0) >= 0.2:
        return {**base, "action": "drop", "source_ip": tt[0]["ip"],
                "reason": f"single heavy source {tt[0]['ip']} ({tt[0]['share']:.0%} of traffic)"}
    # 2. a dominant source port the server never uses -> reflection off that service
    for e in tsp:
        if e.get("port") and e["port"] not in SERVICE_PORTS and e.get("share", 0) >= 0.25:
            proto = "udp" if udp_share >= 0.5 else "tcp"
            return {**base, "action": "drop", "protocol": proto, "src_port": e["port"],
                    "unknown_sources_only": True,
                    "reason": f"reflected replies from {proto.upper()} source port {e['port']}"}
    # 3. handshake-less SYN storm
    if profile.get("syn_to_ack_ratio", 0) > 0.5:
        return {**base, "action": "rate_limit", "protocol": "tcp", "syn_only": True,
                "unknown_sources_only": True, "rate_pps": 200,
                "reason": "many half-open connections from unknown sources"}
    # 4. last resort: rate-limit everything from never-seen sources (trusted players keep passing)
    return {**base, "action": "rate_limit", "protocol": "any", "unknown_sources_only": True,
            "rate_pps": 1000, "reason": "rate-limit unknown sources while the anomaly is unnamed"}


def _parse_rule(raw: str) -> dict | None:
    try:
        start, end = raw.index("{"), raw.rindex("}") + 1
        return json.loads(raw[start:end])
    except (ValueError, json.JSONDecodeError):
        return None


def investigate(engine, evidence: list[str] | None = None, profile: dict | None = None) -> dict:
    """Run the analyst on the current/last incident. Returns the proposal and the
    controller's verdict; accepted rules are installed in dry-run."""
    inc = engine.incident or getattr(engine, "last_incident", None)
    if profile is None:
        profile = (inc or {}).get("profile", {}) or {}
    if evidence is None:
        evidence = (inc or {}).get("evidence", []) or []

    backend = _backend()
    suggestion = None
    raw = ask_llm(f"{ANALYST_SYSTEM}\n\n{_prompt(evidence, profile)}") if backend != "template" else None
    if raw:
        suggestion = _parse_rule(raw)
    if suggestion is None:
        suggestion, backend = _heuristic(profile), (backend if backend == "template" else f"{backend} (fell back to heuristic)")
    if suggestion is None:
        return {"proposed": None, "backend": backend, "verdict": None}

    with engine.lock:
        verdict = validate_suggestion(suggestion, engine.controller, engine.attack_sample,
                                      engine.calm_sample, set(engine.trusted), engine.t)
        engine.store.event(engine.t, "analyst",
                           f"{'accepted (dry-run)' if verdict['accepted'] else 'rejected'}: "
                           f"{verdict['rule']} ({verdict['verdict']})",
                           inc["id"] if inc else None)
    return {"proposed": suggestion, "verdict": verdict, "backend": backend}
