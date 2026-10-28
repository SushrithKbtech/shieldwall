# Live test: ShieldWall on a real Minecraft server

This is not the simulator. A real Minecraft server, a real player bot, and the real
XDP kernel program, under a real flood, on one Linux host. Run by Saran Chekka on Linux.

## Setup

| Piece | What it really was |
|---|---|
| Protected server | **flying-squid** Minecraft server (v1.18.2), listening on a veth interface |
| Real player | **mineflayer** bot connected and playing, plus a server-list ping every second to measure responsiveness |
| Data plane | the **real `bpf/xdp_filter.o`** attached to the server's interface (generic XDP) |
| Control loop | the real `shieldwall live` loop: reads kernel maps, detects, classifies (stats + ML cascade), installs rules via `bpftool` |
| Attack | a real **CLDAP amplification flood** (UDP source port 389) from a separate network namespace, ~300k-500k packets/s |

Two runs, identical except for one switch: **dry-run** (watch only) vs **enforce** (block).

## What happened, second by second (enforce)

| Time | Attack arriving | Kernel dropped | Detector | Classified as |
|---|---|---|---|---|
| t+1 | 315,688 /s | 0 (0%) | - | - |
| t+2 | 307,470 /s | 0 (0%) | **alert** | CLDAP amplification flood |
| t+3 | 346,782 /s | 337,476 /s (**97.3%**) | alert | CLDAP amplification flood |
| t+4 | 467,480 /s | 467,470 /s (**100%**) | alert | CLDAP amplification flood |
| t+5 | 438,742 /s | 438,733 /s (**100%**) | alert | CLDAP amplification flood |
| t+6+ | ~490,000 /s | ~490,000 /s (**100%**) | alert | CLDAP amplification flood |

Detected and named in **~2 seconds**; blocking in the kernel one second later; **~100%**
of the flood dropped from then on. The rule it wrote itself: `DROP UDP src port 389`.

## Dry-run vs enforce

| | Dry-run (watch) | Enforce (block) |
|---|---|---|
| Attack classified | CLDAP amplification flood | CLDAP amplification flood |
| Rule chosen | DROP UDP src port 389 | DROP UDP src port 389 |
| Attack packets dropped by the kernel | **0** | **5,283,933** |
| Player bot | stayed connected | stayed connected |

## Limitation

The player bot stayed connected in **both** runs, and its ping barely moved (≈10-12 ms).
That is **not** because blocking did nothing: the kernel counters show it dropped
5.28 million attack packets. It is because this test machine has **no link bottleneck**: a
veth has effectively unlimited internal bandwidth, the host CPU is fast, and the kernel
modules for a `tc` rate cap were unavailable, so a volumetric flood could not be made to
starve the player here.

On a **real small-server uplink** (say 100 Mbps), that same flood fills the pipe and the
player lags or drops without ShieldWall, and the 100%-drop-in-kernel is exactly what
keeps the link clear. This is the project's known limit restated: a host-side tool proves
detection and local mitigation honestly; it cannot reproduce a true link-filling flood on
a single machine. The kernel drop counts are the honest proof that the mechanism works.

## Reproduce

```bash
# needs Linux, root, clang, libbpf, bpftool and node
make -C bpf
cd mc-demo && npm install
sudo python3 live_demo.py        # runs both dry-run and enforce, writes mc-demo/live_results.json
```
