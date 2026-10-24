"""The LLM layer: explains and assists. It NEVER makes a blocking decision.

Detection and blocking happen in the stats engine in milliseconds. The LLM works on
a human timescale, off the hot path, turning structured incident facts into plain
English and answering questions from the SQL event log.

Backends (env SHIELDWALL_LLM, default "auto"):
  openai     - GPT via the official SDK (needs OPENAI_API_KEY, `pip install openai`);
               model from SHIELDWALL_OPENAI_MODEL, default gpt-4o-mini (the cheapest mini model)
  anthropic  - Claude via the official SDK (needs ANTHROPIC_API_KEY, `pip install anthropic`)
  ollama     - a local model through Ollama (SHIELDWALL_OLLAMA_MODEL, default llama3.2)
  template   - deterministic built-in wording, no network
"auto" picks openai, then anthropic, when their key and SDK are present, else template.
Any backend error falls back to the template, so the demo never breaks.
"""
from __future__ import annotations

import json
import os
import urllib.request

from .store import EventStore

SYSTEM = (
    "You are ShieldWall's assistant. You explain DDoS incidents on a small game server to a "
    "non-expert owner. Be short, calm and concrete: what happened, what ShieldWall did, whether "
    "players were affected, and whether the owner needs to do anything. Use only the facts given. "
    "State numbers exactly as given and add nothing beyond them: for example, do not say 'no impact' or "
    "'no disruption' unless served_pct is 100, and do not guess at things the facts don't mention. "
    "You never block traffic yourself; the statistics engine does that."
)


def _has_sdk(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


def _backend() -> str:
    choice = os.environ.get("SHIELDWALL_LLM", "auto").lower()
    if choice != "auto":
        return choice
    if os.environ.get("OPENAI_API_KEY") and _has_sdk("openai"):
        return "openai"
    if os.environ.get("ANTHROPIC_API_KEY") and _has_sdk("anthropic"):
        return "anthropic"
    return "template"


def backend_label() -> str:
    """Which model is explaining, for the dashboard."""
    b = _backend()
    if b == "openai":
        return os.environ.get("SHIELDWALL_OPENAI_MODEL", "gpt-4o-mini")
    if b == "anthropic":
        return "claude-opus-5-5"
    if b == "ollama":
        return os.environ.get("SHIELDWALL_OLLAMA_MODEL", "llama3.2")
    return "built-in template"


def _ask_openai(prompt: str) -> str:
    from openai import OpenAI

    client = OpenAI(timeout=30)
    response = client.chat.completions.create(
        model=os.environ.get("SHIELDWALL_OPENAI_MODEL", "gpt-4o-mini"),
        max_tokens=300,
        temperature=0.3,
        messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
    )
    return (response.choices[0].message.content or "").strip()


def _ask_anthropic(prompt: str) -> str:
    import anthropic

    client = anthropic.Anthropic()
    response = client.beta.messages.create(
        model="claude-opus-5-5",
        max_tokens=1024,
        system=SYSTEM,
        output_config={"effort": "low"},
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        messages=[{"role": "user", "content": prompt}],
    )
    if response.stop_reason == "refusal":
        raise RuntimeError("model declined")
    return "".join(b.text for b in response.content if b.type == "text").strip()


def _ask_ollama(prompt: str) -> str:
    body = json.dumps({
        "model": os.environ.get("SHIELDWALL_OLLAMA_MODEL", "llama3.2"),
        "system": SYSTEM,
        "prompt": prompt,
        "stream": False,
    }).encode()
    req = urllib.request.Request("http://localhost:11434/api/generate", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())["response"].strip()


def ask_llm(prompt: str) -> str | None:
    backend = _backend()
    try:
        if backend == "openai":
            return _ask_openai(prompt)
        if backend == "anthropic":
            return _ask_anthropic(prompt)
        if backend == "ollama":
            return _ask_ollama(prompt)
    except Exception:
        return None
    return None


# -- incident explanations ---------------------------------------------------

def template_explanation(facts: dict) -> str:
    if not facts.get("malicious"):
        return (f"Traffic jumped to {facts['peak_pps']:,.0f} packets/s, but it looks like real players "
                f"(handshakes complete, normal protocol mix). ShieldWall is watching and did not block anyone.")
    s = (f"Your server was attacked from about {facts['sources']:,} sources using a "
         f"{facts['label']} at up to {facts['peak_pps']:,.0f} packets/s. ")
    if facts.get("mitigate_s") is not None:
        s += f"ShieldWall blocked it {facts['mitigate_s']:.0f} seconds after it started. "
    if facts.get("served_pct") is not None:
        s += f"{facts['served_pct']:.0f}% of real player traffic got through during the attack. "
    elif facts.get("mitigate_s") is not None:
        s += "Real players are getting through normally again. "
    if facts.get("escalated"):
        s += "The flood was bigger than your internet link, so ShieldWall asked the upstream network to filter it. "
    s += "No action needed from you."
    return s


FIELD_GUIDE = (
    "Field meanings: peak_pps = highest packets per second seen; sources = distinct sending addresses; "
    "detect_s = seconds from the start of the traffic change until ShieldWall confirmed it; "
    "mitigate_s = seconds from the start until blocking took effect (null = nothing blocked yet); "
    "served_pct = percent of real player traffic that got through during the incident (null until the incident "
    "is over); incident_over = false means the attack is still happening right now; blocking_now = true means "
    "ShieldWall is actively dropping the attack traffic at this moment; "
    "escalated = the flood exceeded the internet link and the provider was asked to filter it; "
    "malicious = false means real players, not an attack."
)


def incident_prompt(facts: dict) -> str:
    return ("Explain this incident to the server owner in 2-3 sentences.\n"
            f"{FIELD_GUIDE}\nFacts (JSON): {json.dumps(facts, default=str)}")


def explain_incident(facts: dict) -> str:
    return ask_llm(incident_prompt(facts)) or template_explanation(facts)


# -- chat over telemetry -----------------------------------------------------

def _template_answer(question: str, store: EventStore) -> str:
    q = question.lower()
    incidents = store.incidents(10)
    events = store.recent_events(15)
    if not incidents:
        return "All quiet so far: no attacks or traffic surges have been detected."
    last = incidents[0]
    if "why" in q and ("block" in q or "port" in q or "drop" in q):
        ev = json.loads(last["evidence"] or "[]")
        return f"For incident #{last['id']} ({last['label']}) the evidence was: " + "; ".join(ev) + "."
    if "how many" in q:
        attacks = sum(1 for i in incidents if i["malicious"])
        return f"{attacks} attack(s) and {len(incidents) - attacks} non-malicious surge(s) in the log."
    if any(w in q for w in ("rule", "active", "blocking")):
        rules = [e["detail"] for e in events if e["kind"] in ("rule_added", "escalated")]
        return ("Recent rules: " + "; ".join(rules[:5])) if rules else "No rules have been added recently."
    return last["explanation"] or template_explanation({
        "malicious": bool(last["malicious"]), "label": last["label"], "peak_pps": last["peak_pps"] or 0,
        "sources": last["sources"] or 0})


def chat_prompt(question: str, store: EventStore) -> str:
    context = {
        "incidents": store.incidents(10),
        "recent_events": store.recent_events(30),
    }
    return ("Answer the owner's question using only this event log.\n"
            f"Event log (JSON): {json.dumps(context, default=str)}\n\nQuestion: {question}")


def answer_question(question: str, store: EventStore) -> str:
    return ask_llm(chat_prompt(question, store)) or _template_answer(question, store)
