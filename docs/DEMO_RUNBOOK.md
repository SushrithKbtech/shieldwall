# ShieldWall demo runbook

How to reproduce the three detection tiers, the real-kernel tests and the live Minecraft
test on your own Linux PC (or WSL2).

## 0. Prerequisites

```bash
sudo apt install clang llvm libbpf-dev linux-tools-generic python3-pip python3-scapy nodejs npm
pip install -e ".[ml]"           # scikit-learn 1.7.2 + joblib, the version the shipped model was trained with
make -C bpf                      # builds bpf/xdp_filter.o
```

## 1. The trained ML model (Tier 2)

```bash
shieldwall ml-train                                  # simulator only
shieldwall ml-train --captures DEV_DIR --heldout HELDOUT_DIR \
    --cic archive.zip --cic-dev 01-12/Syn.csv --cic-heldout 01-12/UDPLag.csv
```

Writes `results/ml_model.joblib` and `results/ml_eval.md`. The shipped model learns from
simulated seconds only and is scored on the real captures, which it never saw. Its headline:
it names the SYN-ACK reflection attack that no fingerprint matches. Add `--cache FILE` to
keep the generated windows between runs.

## 2. The cascade and the analyst (Tier 3)

```bash
pytest -q                        # unit, replay, cascade, analyst and end-to-end tests
shieldwall analyst-eval --captures DEV_DIR --captures HELDOUT_DIR   # LLM vs heuristic rule proposals
```

`cascade.py` routes every flagged second: fingerprints name known signatures, the ML model
names what has no signature, and anything neither can name goes to the analyst
(`analyst.py`), which proposes one rule that the controller validates and installs in
dry-run. With `OPENAI_API_KEY` set, gpt-4o-mini does the reasoning; with no key a
deterministic heuristic stands in, so the pipeline runs offline.

## 3. Real kernel

```bash
sudo bash tests/xdp_kernel_test.sh                                 # every kernel feature, incl. the SYN-ACK rule
sudo bash tests/xdp_replay_test.sh amp.TCP.reflection.SYNACK.pcap  # a real capture through the real XDP program
sudo bash tests/xdp_replay_test.sh amp.TCP.reflection.SYNACK.pcap analyst   # the live Tier 3 path
```

## 4. Live Minecraft test

`mc-demo/` runs a real Minecraft server (flying-squid), a real player bot (mineflayer), the
real XDP program and a real CLDAP flood, comparing dry-run with enforce.

```bash
cd mc-demo
npm install
sudo python3 live_demo.py        # writes mc-demo/live_results.json
```

flying-squid 1.12 crashes on join unless `'player-list-text': { header: '', footer: '' }` is
passed to `createMCServer` (already set in `mc_server.js`).

### Showing it on a real server

1. Run a PaperMC server on your own machine, accept the EULA, and set `online-mode=false` for test bots.
2. `sudo shieldwall live --iface <your-iface> --dry-run` against normal traffic for a while: this
   gives a false-alarm count on real traffic.
3. Join with the real Minecraft client and play.
4. From a second machine on a capacity-limited link, replay a recorded public capture. With a real
   uplink limit the player lags in dry-run and stays smooth in enforce, which a single host with a
   veth pair cannot show (it has no link bottleneck).

Keep all attack traffic inside your own lab. Never point a flood at a cloud host or at anything
you do not own; every provider's acceptable-use policy forbids it.
