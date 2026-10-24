# ShieldWall

**An automatic, self-explaining bouncer for small servers.**
ShieldWall watches all traffic to one server, detects a DDoS attack in about 2 seconds, drops the attack traffic in the Linux kernel while real players keep playing, and explains in plain English what happened.

`C (eBPF/XDP) drops · Python decides · the LLM explains · SQLite remembers`

![ShieldWall live monitor during a CLDAP amplification attack](docs/tab_live.png)

The dashboard has three tabs, written so anyone can follow along:

| Live monitor | How it works | Results |
|---|---|---|
| Plain-English status ("Under attack: CLDAP amplification flood. ShieldWall is blocking it."), a 5-step tracker, the three alarms, what is being blocked, a timeline, and the AI assistant | Each model explained with a question, an everyday analogy and its live value | Accuracy, precision, recall, F1, confusion matrix, per-attack detection, with vs without ShieldWall, kernel test and LLM evaluation |
| ![Live](docs/tab_live.png) | ![How it works](docs/tab_how.png) | ![Results](docs/tab_results.png) |

## Highlights

- **Kernel-speed blocking.** An eBPF/XDP program drops attack packets inside the NIC driver, before the kernel network stack does any work.
- **No fixed thresholds.** Three statistical detectors vote (EWMA z-score, CUSUM, entropy), with persistence and absolute-floor guards against false alarms.
- **Knows what hit you.** Fingerprints DNS, NTP and CLDAP amplification, SYN floods and UDP floods, and tells a real rush of players apart from an attack.
- **Safe by design.** Every rule expires, an allowlist is never dropped, the rule count is capped, and a dry-run mode logs without dropping.
- **Grows with your server.** A sustained legitimate surge becomes the new normal, so busy evenings don't trigger alerts.
- **Escalates when the pipe is full.** If a flood exceeds the uplink, the drop rule is announced upstream as BGP FlowSpec.
- **Explains itself.** gpt-4o-mini turns each incident into a plain-English summary and answers questions from the event log, grounded only in verified facts. It never makes a blocking decision, and its answers are evaluated for hallucinations.
- **No training needed.** The detectors learn what normal traffic looks like from the first seconds of traffic and keep adapting.

## Results

### Detection quality: 60 randomized trials

52 attacks (CLDAP, DNS, NTP, SYN, UDP at 3k-300k pps, random timing and ramp) and 8 negatives (flash crowds of real players, quiet traffic). Full report: [results/metrics.md](results/metrics.md).

| Level | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Per 1-second window | 97.96% | **100%** | 94.98% | 0.974 |
| Per packet dropped | 96.81% | **100%** | 96.45% | 0.982 |
| Per attack (incident) | 98.33% | **100%** | 98.08% | 0.990 |

- **Zero false positives**: no flash crowd or quiet run was ever mitigated; 0.015% of real traffic was dropped across all trials.
- **100%** attack-type classification accuracy on caught attacks; median time to detect **2 s**.
- Window recall is below 100% by design: the 2-window persistence guard counts the first seconds of every attack as misses. That guard is what keeps precision at 100%.

**What the metrics mean.** *Precision*: when ShieldWall says "attack", how often it really is one (low precision means blocking real players). *Recall*: of all real attack time, how much it caught. *F1*: the balance of the two. Ground truth comes from the traffic generator, which knows exactly when each attack runs.

### Four scenarios, with vs without ShieldWall

Same seeded traffic, once enforcing and once in dry-run ("without"). ~2,000 pps of Minecraft players, server capacity 60k pps, 10 Gbps uplink. Full report: [results/results.md](results/results.md).

| Scenario | Classified as | Real traffic served WITHOUT | WITH | Detect | Mitigate |
|---|---|---|---|---|---|
| S1 Clean attack (CLDAP amplification, 200k pps) | CLDAP amplification | 30.2% | **98.1%** | 2 s | 3 s |
| S2a Mixed with real traffic (SYN flood on the game port) | TCP SYN flood | 40.1% | **98.7%** | 2 s | 3 s |
| S2b Mixed with real traffic (UDP flood) | UDP flood | 50.3% | **99.3%** | 2 s | 3 s |
| S3 Legit surge, no attack (flash crowd) | legitimate surge | 100% | **100%, 0 rules** | 3 s | n/a |
| S4 Bigger than the link (25 Gbps into 10 Gbps) | CLDAP amplification | 2.8% | **95.7%** (FlowSpec upstream) | 2 s | 4 s |

### The LLM: is it correct, fast and cheap?

`shieldwall llm-eval` sends the exact production prompts for 13 real incidents and 3 chat questions to gpt-4o-mini and scores every answer automatically. Full report: [results/llm_eval.md](results/llm_eval.md).

| Metric | Result |
|---|---|
| Numbers in its answers that match the facts it was given (hallucination check) | **100%** (49/49, zero made-up numbers) |
| Names the correct attack, or calls a surge real players | **100%** |
| Chat answers over the event log that contain the right answer | **100%** |
| Median latency (runs in the background, never delays blocking) | 1.6 s |
| Cost per explanation | $0.00008 |

### On a real Linux kernel

[tests/xdp_kernel_test.sh](tests/xdp_kernel_test.sh) loads the XDP program on a veth interface, replays a CLDAP reflection flood from 500 spoofed sources with scapy, and runs the live control plane against the real BPF maps:

```
normal window : 400 pkts, amp share 0%, 20 sources
attack window : 3000 pkts, amp share 100% from port 389, ~506 sources -> CLDAP amplification flood
with rule     : kernel dropped 3000 attack pkts, passed 400 player pkts, rule hits 3000
dry-run       : dropped 0 (should be 0)
KERNEL TEST PASSED
```

The program passes the kernel verifier and is JIT-compiled (tested on Linux 6.18).

## How it works

```
                 Attacker botnet            Real players
                        \                      /
                         v                    v
  KERNEL  (C / eBPF)  +-------------------------------------+
  data plane          |  XDP program: parse -> count -> drop |  every packet, microseconds
                      +-------------------------------------+
                           |  counter maps     ^  rule maps
                           v  (read)           |  (write)
  USERSPACE (Python)  +-------------------------------------+
  control plane       |  featurise -> detect -> classify ->  |  once a second
                      |  mitigate (expiring rules, safety)   |
                      +-------------------------------------+
                           |                    |
                    LLM assistant          SQLite event log -> dashboard
                    (explains, never blocks)
```

**Two clocks.** The kernel does the cheap, high-volume work (count and drop) on every packet. Userspace does the expensive thinking (detect and decide) once a second. BPF maps are the only bridge.

### 1. Data plane: [bpf/xdp_filter.c](bpf/xdp_filter.c)
Four jobs only: parse headers, count into maps, check allowlist and rules, drop or pass. It counts *before* dropping, so the detector keeps seeing an attack while it's being blocked. Maps: `stats`, `src_count`, `udp_sport_count`, `rules` (capped at 64), `allowlist` (LPM trie), `trusted`, `config` (enforce / dry-run).

### 2. Detection: three methods vote ([detectors.py](controlplane/shieldwall/detectors.py))
| Method | Formula | Catches |
|---|---|---|
| EWMA baseline + z-score | `z = (x - mu) / sigma` | sudden spikes |
| CUSUM | `S_t = max(0, S_{t-1} + z_t - k)` | slow ramps a single z-score misses |
| Entropy | `H = -sum p_i log2 p_i` over source IPs | botnets spreading traffic across new sources |

An alert needs 2 of 3 votes, must persist for 2 windows, and must clear an absolute floor (a 3 a.m. blip from 10 to 30 pps never fires). The baseline freezes during anomalies so an attack never becomes "normal"; only a surge confirmed as legitimate for 30 s is adopted as the new baseline.

### 3. Probabilistic data structures ([sketches.py](controlplane/shieldwall/sketches.py))
| Structure | Question | Memory |
|---|---|---|
| Count-Min Sketch | who are the top talkers? | 64 KB |
| HyperLogLog | how many unique sources? | 1 KB, ~3% error |
| Bloom filter | have I seen this source before? | ~240 KB for 200k sources |

### 4. Classify by fingerprint ([classifier.py](controlplane/shieldwall/classifier.py))
| Attack | Fingerprint |
|---|---|
| DNS / NTP / CLDAP amplification | UDP arriving *from* a service port the server never uses (53, 123, 389...) |
| SYN flood | SYNs outnumber ACKs (normal is about 1 SYN per 100 ACKs) |
| UDP flood | UDP share jumps, mostly never-seen sources, sprayed ports |
| Legit surge | volume up, but handshakes complete and the protocol mix is normal |

### 5. Mitigation ([mitigation.py](controlplane/shieldwall/mitigation.py))
Signature drop for clean fingerprints, token-bucket rate limit for the rest (sources that completed handshakes in calm times keep passing). Every rule expires after 60 s and is renewed only while it still matches traffic. Graduated response: observe, rate-limit, drop, escalate. If the link itself is full for 3 windows, the drop rule goes upstream as BGP FlowSpec.

### 6. LLM layer ([llm.py](controlplane/shieldwall/llm.py))
Runs in a background thread, off the hot path, so blocking never waits for it (an explanation takes ~2-3 s; blocking takes milliseconds). Backends, picked automatically from the keys you have:

| Backend | Setup | Notes |
|---|---|---|
| OpenAI `gpt-4o-mini` (default when a key is set) | `pip install openai`, set `OPENAI_API_KEY` | cheapest mini model; override with `SHIELDWALL_OPENAI_MODEL` |
| Claude | `pip install anthropic`, set `ANTHROPIC_API_KEY` | |
| Ollama | `SHIELDWALL_LLM=ollama` | runs a local model |
| Built-in template | nothing | used when no key is set, and as the fallback on any error |

> **gpt-4o-mini:** "Your game server experienced a CLDAP amplification flood attack, peaking at over 213,000 packets per second from 2,204 sources. ShieldWall detected and mitigated the attack quickly, allowing 98.1% of legitimate traffic to be served without significant disruption. There's no action needed on your part, as the incident has been resolved."
>
> **Asked "why did you block port 389?":** "We blocked UDP source port 389 because your server was targeted by a CLDAP amplification flood attack... blocking this port helped mitigate the attack."

## Run it

Needs Python 3.10+. The core has no dependencies.

```bash
git clone https://github.com/SushrithKbtech/shieldwall.git
cd shieldwall
pip install -e .
```

| Command | What it does |
|---|---|
| `shieldwall dashboard` | live dashboard at http://127.0.0.1:8000; click an attack button |
| `shieldwall demo --attack cldap` | one attack, step by step in the terminal |
| `shieldwall eval` | four-scenario evaluation -> `results/results.md` |
| `shieldwall metrics` | accuracy / precision / recall / F1 -> `results/metrics.md` |
| `shieldwall llm-eval` | LLM grounding, accuracy, latency and cost -> `results/llm_eval.md` (needs `OPENAI_API_KEY`) |
| `pytest -q` | unit and end-to-end tests (`pip install pytest`) |

Plain-English explanations from GPT instead of the built-in template:
```bash
pip install openai
export OPENAI_API_KEY=...
```

### On Linux with the real XDP program

```bash
sudo apt install clang llvm libbpf-dev linux-tools-generic python3-scapy
make -C bpf
sudo bash tests/xdp_kernel_test.sh                 # kernel test on a veth pair
sudo shieldwall live --iface eth0 --dry-run        # protect a real interface, log only
sudo shieldwall live --iface eth0                  # enforce
```

## Repo layout

```
bpf/xdp_filter.c              kernel data plane (C, eBPF/XDP)
controlplane/shieldwall/
  sketches.py                 Count-Min, HyperLogLog, Bloom
  features.py                 counters -> features (rates, ratios, entropy)
  detectors.py                EWMA z-score, CUSUM, entropy vote, re-baselining
  classifier.py               attack fingerprints, legit-surge check
  mitigation.py               expiring rules, safety, upstream escalation
  bpf_dataplane.py            live loader for the real XDP maps (Linux)
  simulator.py                lab traffic generator: players, attacks, link, server
  engine.py                   the per-second control loop
  llm.py                      explainer + chat
  store.py                    SQLite event log
  server.py, ../dashboard/    live dashboard
  evaluate.py, metrics.py     scenario evaluation, accuracy/precision/recall/F1
  llm_eval.py                 LLM grounding / accuracy / latency / cost evaluation
tests/                        unit, end-to-end and kernel tests
results/                      latest evaluation and metrics
docs/SCRIPT.md                presentation script
```

## Known limits

- If a flood is bigger than the server's uplink, nothing on the server can fix it; ShieldWall's answer is upstream FlowSpec, which needs a provider that accepts it.
- The detection metrics use the built-in traffic generator for ground truth. Results on real captures (for example CIC-DDoS2019) will differ.
- IPv4 only; IPv6 traffic is passed through untouched. HTTP (layer 7) floods are not classified.
- The live loader reads maps through `bpftool`, which is fine up to tens of thousands of sources; a libbpf reader would be needed for much larger botnets.

## Safety and ethics

All attack traffic is generated inside an isolated lab with no route to the internet. Never point attack tools at anything you don't own, and never use stresser services.
