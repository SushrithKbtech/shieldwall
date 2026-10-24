"""ShieldWall CLI.

    python -m shieldwall dashboard            live dashboard on http://127.0.0.1:8000
    python -m shieldwall demo --attack cldap  terminal run of one scenario
    python -m shieldwall eval                 four-scenario evaluation -> results/results.md
    python -m shieldwall metrics              accuracy / precision / recall / F1 -> results/metrics.md
    sudo python -m shieldwall live --iface eth0   real XDP data plane (Linux)
"""
from __future__ import annotations

import argparse
import os
import sys

from .engine import PRESETS


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="shieldwall", description="Detect, mitigate and explain DDoS attacks.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("dashboard", help="run the live dashboard (simulated lab)")
    d.add_argument("--host", default="127.0.0.1")
    d.add_argument("--port", type=int, default=8000)
    d.add_argument("--speed", type=float, default=1.0, help="control-loop windows per real second")

    demo = sub.add_parser("demo", help="run one scenario in the terminal")
    demo.add_argument("--attack", choices=list(PRESETS), default="cldap")
    demo.add_argument("--dry-run", action="store_true")

    e = sub.add_parser("eval", help="run the four-scenario evaluation")
    e.add_argument("--out", default=os.path.join("results", "results.md"))

    m = sub.add_parser("metrics", help="accuracy, precision, recall, F1 over randomized trials")
    m.add_argument("--trials", type=int, default=60)
    m.add_argument("--out", default=os.path.join("results", "metrics.md"))

    live = sub.add_parser("live", help="attach the real XDP program (Linux, root)")
    live.add_argument("--iface", required=True)
    live.add_argument("--obj", default=os.path.join("bpf", "xdp_filter.o"))
    live.add_argument("--dry-run", action="store_true")

    args = ap.parse_args(argv)
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8")

    if args.cmd == "dashboard":
        from .server import serve
        serve(args.host, args.port, args.speed)
    elif args.cmd == "demo":
        run_demo(args.attack, args.dry_run)
    elif args.cmd == "eval":
        from .evaluate import main as evaluate
        evaluate(args.out)
    elif args.cmd == "metrics":
        from .metrics import main as metrics
        metrics(args.trials, args.out)
    elif args.cmd == "live":
        from .bpf_dataplane import run_live
        run_live(args.iface, args.dry_run, args.obj)


def run_demo(attack: str, dry_run: bool) -> None:
    from .engine import Engine
    from .mitigation import MitigationConfig

    os.environ.setdefault("SHIELDWALL_LLM", "template")
    eng = Engine(mit_cfg=MitigationConfig(dry_run=dry_run), explain_async=False)
    eng.launch(attack, duration=30, start=30)
    seen_events = 0
    for _ in range(90):
        p = eng.step()
        bar = "#" * min(50, int(p["pps"] / 5000))
        flag = "ALERT" if p["anomalous"] else "     "
        print(f"t={p['t']:3d}s {flag} {p['pps']:>10,} pps  served {p['served_pct']:5.1f}%  "
              f"z={p['zscore']:>7.1f}  {p['stage']:<10} {bar}")
        events = eng.store.query("SELECT * FROM events ORDER BY id")
        for ev in events[seen_events:]:
            print(f"        >> [{ev['kind']}] {ev['detail']}")
        seen_events = len(events)
    inc = eng.store.incidents(1)
    if inc:
        print("\nShieldWall says:", inc[0]["explanation"])


if __name__ == "__main__":
    main()
