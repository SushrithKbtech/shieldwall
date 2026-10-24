"""LLM post-incident report + rule suggestions that the controller validates.

gpt-4o-mini receives the incident facts (with their meanings), the traffic profile at
the attack's peak, the rules ShieldWall applied and the incident's event log. It
returns a structured report (strict JSON schema) and up to three extra rules. Each
suggested rule is checked by mitigation.validate_suggestion against real traffic
samples; only safe, relevant rules are installed, and only in dry-run.
"""
from __future__ import annotations

import json
import os

from .llm import FIELD_GUIDE, _backend
from .mitigation import validate_suggestion

SYSTEM = (
    "You are ShieldWall's incident analyst for a small game server (Minecraft: TCP 25565, UDP 19132). "
    "Write a short, factual post-incident report for the server owner using only the facts given. "
    "Then suggest up to 3 additional mitigation rules that would help against this specific attack. "
    "ShieldWall's controller will test every suggestion against real traffic and reject unsafe or useless ones, "
    "so prefer narrow rules (a source port, fragments, SYN-only, or unknown sources only). Suggest a source_ip "
    "only if that single address sends at least 20% of all traffic (see the share in top_talkers); a distributed "
    "attack from many addresses needs port, fragment or SYN rules instead. Do not repeat rules already applied. "
    "Never suggest a rule "
    "that would block the game ports for everyone. If no extra rule would help, return an empty list."
)

RULE = {
    "type": "object", "additionalProperties": False,
    "required": ["action", "protocol", "source_ip", "src_port", "dst_port", "syn_only", "fragments_only",
                 "unknown_sources_only", "rate_pps", "reason"],
    "properties": {
        "action": {"type": "string", "enum": ["drop", "rate_limit"]},
        "protocol": {"type": "string", "enum": ["udp", "tcp", "any"]},
        "source_ip": {"type": ["string", "null"]},
        "src_port": {"type": ["integer", "null"]},
        "dst_port": {"type": ["integer", "null"]},
        "syn_only": {"type": "boolean"},
        "fragments_only": {"type": "boolean"},
        "unknown_sources_only": {"type": "boolean"},
        "rate_pps": {"type": ["integer", "null"]},
        "reason": {"type": "string"},
    },
}
SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["title", "summary", "timeline", "impact", "actions_taken", "recommendations", "rule_suggestions"],
    "properties": {
        "title": {"type": "string"},
        "summary": {"type": "string"},
        "timeline": {"type": "array", "items": {"type": "string"}},
        "impact": {"type": "string"},
        "actions_taken": {"type": "array", "items": {"type": "string"}},
        "recommendations": {"type": "array", "items": {"type": "string"}},
        "rule_suggestions": {"type": "array", "items": RULE},
    },
}


def gather(engine) -> dict | None:
    inc = engine.incident or getattr(engine, "last_incident", None)
    if inc is None:
        return None
    events = engine.store.query("SELECT t, kind, detail FROM events WHERE incident_id = ? ORDER BY id", (inc["id"],))
    t0 = inc["attack_start"] if inc.get("attack_start") is not None else inc["start"]
    return {
        "facts": engine._facts(inc),
        "traffic_at_peak": inc.get("profile", {}),
        "rules_applied": [r.describe() for r in engine.controller.rules.values() if r.mode == "enforce"],
        "upstream_filters": [r.describe() for r in engine.controller.upstream_rules.values()],
        "event_log (seconds after the traffic change began)": [f"+{e['t'] - t0}s {e['kind']}: {e['detail']}"
                                                                for e in events],
    }


def _ask_openai(context: dict) -> tuple[dict, dict]:
    from openai import OpenAI

    client = OpenAI(timeout=60)
    r = client.chat.completions.create(
        model=os.environ.get("SHIELDWALL_OPENAI_MODEL", "gpt-4o-mini"),
        temperature=0.2,
        max_tokens=900,
        response_format={"type": "json_schema", "json_schema": {"name": "incident_report", "strict": True, "schema": SCHEMA}},
        messages=[
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"{FIELD_GUIDE}\n\nIncident (JSON): {json.dumps(context, default=str)}"},
        ],
    )
    usage = {"tokens_in": r.usage.prompt_tokens, "tokens_out": r.usage.completion_tokens}
    return json.loads(r.choices[0].message.content), usage


def _template(context: dict) -> dict:
    f = context["facts"]
    return {
        "title": f"Incident #{f['incident']}: {f['label']}",
        "summary": f"{f['label']} at up to {f['peak_pps']:,} packets/s from about {f['sources']:,} sources.",
        "timeline": context["event_log (seconds after the traffic change began)"],
        "impact": (f"{f['served_pct']}% of real player traffic was served." if f.get("served_pct") is not None
                   else "Incident still open."),
        "actions_taken": context["rules_applied"] + [f"upstream: {u}" for u in context["upstream_filters"]],
        "recommendations": [],
        "rule_suggestions": [],
    }


def to_markdown(rep: dict, checked: list[dict]) -> str:
    lines = [f"## {rep['title']}", "", rep["summary"], "", "**Timeline**", *[f"- {x}" for x in rep["timeline"]], "",
             f"**Impact:** {rep['impact']}", "", "**Actions taken**", *[f"- {x}" for x in rep["actions_taken"]], ""]
    if rep["recommendations"]:
        lines += ["**Recommendations**", *[f"- {x}" for x in rep["recommendations"]], ""]
    if checked:
        lines += ["**Suggested rules (checked by the controller)**",
                  *[f"- {'✓' if c['accepted'] else '✗'} {c['rule']}: {c['verdict']}" for c in checked], ""]
    return "\n".join(lines)


def incident_report(engine) -> dict:
    context = gather(engine)
    if context is None:
        return {"available": False, "markdown": "No incident to report on yet."}
    usage, backend = {}, _backend()
    try:
        rep, usage = _ask_openai(context) if backend == "openai" else (_template(context), {})
    except Exception as e:  # never let the report break the engine
        rep, backend = _template(context), f"template (LLM error: {type(e).__name__})"
    with engine.lock:
        checked = [validate_suggestion(s, engine.controller, engine.attack_sample, engine.calm_sample,
                                       set(engine.trusted), engine.t) for s in rep.get("rule_suggestions", [])[:3]]
        for c in checked:
            engine.store.event(engine.t, "suggestion", f"{'accepted (dry-run)' if c['accepted'] else 'rejected'}: "
                               f"{c['rule']} ({c['verdict']})", context["facts"]["incident"])
    return {"available": True, "backend": backend, "report": rep, "suggestions": checked, "usage": usage,
            "markdown": to_markdown(rep, checked)}
