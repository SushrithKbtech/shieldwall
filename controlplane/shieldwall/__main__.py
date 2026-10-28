"""ShieldWall CLI.

    python -m shieldwall dashboard            live dashboard on http://127.0.0.1:8000
    python -m shieldwall demo --attack cldap  terminal run of one scenario
    python -m shieldwall eval                 four-scenario evaluation -> results/results.md
    python -m shieldwall metrics              accuracy / precision / recall / F1 -> results/metrics.md
    python -m shieldwall llm-eval             LLM grounding, accuracy, latency, cost -> results/llm_eval.md
    python -m shieldwall replay a.pcap b.pcap real attack captures through the engine -> results/replay.md
    python -m shieldwall ml-train             train the Tier 2 ML classifier -> results/ml_model.joblib, ml_eval.md
    python -m shieldwall analyst-eval         Tier 3 analyst: LLM vs heuristic proposals -> results/analyst_eval.md
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
    m.add_argument("--trials", type=int, default=200)
    m.add_argument("--out", default=os.path.join("results", "metrics.md"))

    le = sub.add_parser("llm-eval", help="evaluate the LLM explanations (needs OPENAI_API_KEY)")
    le.add_argument("--out", default=os.path.join("results", "llm_eval.md"))
    le.add_argument("--seed-offset", type=int, default=0, help="use unseen incidents, e.g. 1000 for a held-out set")

    rp = sub.add_parser("replay", help="replay real attack captures (.pcap/.pcapng) through the engine")
    rp.add_argument("captures", nargs="+")
    rp.add_argument("--target", help="victim IP (default: most common destination)")
    rp.add_argument("--report", action="store_true", help="also write an LLM incident report per capture")
    rp.add_argument("--out", default="results")
    rp.add_argument("--name", default="replay", help="output file stem")

    rc = sub.add_parser("replay-cic", help="replay CIC-DDoS2019 flow records (CSV or the dataset zip)")
    rc.add_argument("path", help="archive.zip or a single CSV")
    rc.add_argument("--member", action="append", help="CSV inside the zip, e.g. 01-12/Syn.csv (repeatable)")
    rc.add_argument("--report", action="store_true")
    rc.add_argument("--out", default="results")
    rc.add_argument("--name", default="replay_cic", help="output file stem")

    mt = sub.add_parser("ml-train", help="train and evaluate the Tier 2 ML classifier (needs scikit-learn)")
    mt.add_argument("--out", default="results")
    mt.add_argument("--captures", action="append", help="folder of development captures the model may learn from")
    mt.add_argument("--heldout", action="append", help="folder of held-out captures, only used for scoring")
    mt.add_argument("--cic", help="CIC-DDoS2019 archive.zip")
    mt.add_argument("--cic-dev", action="append", help="CIC CSV the model may learn from, e.g. 01-12/Syn.csv")
    mt.add_argument("--cic-heldout", action="append", help="CIC CSV only used for scoring")
    mt.add_argument("--cache", help="pickle file that keeps the generated windows between runs")
    mt.add_argument("--learn-from-captures", action="store_true",
                    help="ship the model that also learned from the development captures")

    ae = sub.add_parser("analyst-eval", help="score the Tier 3 analyst's rule proposals (LLM needs OPENAI_API_KEY)")
    ae.add_argument("--out", default="results")
    ae.add_argument("--captures", action="append", help="folder of real attack captures")
    ae.add_argument("--cic", help="CIC-DDoS2019 archive.zip")
    ae.add_argument("--cic-member", action="append", help="CIC CSV inside the zip, e.g. 01-12/Syn.csv")

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
    elif args.cmd == "llm-eval":
        from .llm_eval import main as llm_eval
        llm_eval(args.out, args.seed_offset)
    elif args.cmd == "replay":
        from .replay import main as replay
        replay(args.captures, args.out, args.target, args.report, args.name)
    elif args.cmd == "replay-cic":
        from .replay import main_cic
        main_cic(args.path, args.member or [None], args.out, args.report, args.name)
    elif args.cmd == "ml-train":
        from .ml_train import main as ml_train
        ml_train(args.out, args.captures, args.heldout, args.cic, args.cic_dev, args.cic_heldout, args.cache,
                 args.learn_from_captures)
    elif args.cmd == "analyst-eval":
        from .analyst_eval import main as analyst_eval
        analyst_eval(args.out, args.captures, args.cic, args.cic_member)
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
