# Replay of real DDoS captures

Real attack packets (sources, ports, sizes, flags, fragments) from public captures, replayed at their own packet rate for 30 s on top of modelled player traffic (~2,000 pps). Ground truth = which packets came from the capture. Captures: github.com/StopDDoS/packet-captures ("packet captures of real-world ddos attacks"). Reproduce with `shieldwall replay <file.pcap>`.

| Capture | What is in it | Classified as | Detect | Block | Attack dropped: whole attack (once blocking) | Real traffic dropped | Players served (without → with) | Precision / recall / F1 (per second) |
|---|---|---|---|---|---|---|---|---|
| amp.dns.RRSIG.fragmented.pcap | 4,397 pkts, 148 pps, 237 sources, 16% fragments | not detected | - s | - s | 0.0% (0.0%) | 0.000% | 100.0% → 100.0% | 1.000 / 0.000 / 0.000 |
| amp.TCP.reflection.SYNACK.pcap | 7,996 pkts, 54,465 pps, 7,055 sources, 0% fragments | TCP SYN-ACK reflection flood (ML model) | 2 s | - s | 77.4% (0.0%) | 0.000% | 100.0% → 100.0% | 1.000 / 0.967 / 0.983 |
| amp.UDP.isakmp.pcap | 3,984 pkts, 9,744 pps, 2,767 sources, 0% fragments | UDP flood | 2 s | 3 s | 87.5% (93.8%) | 0.265% | 100.0% → 99.1% | 1.000 / 0.967 / 0.983 |
| amp.UDP.snmp.src161.pcapng | 4,373 pkts, 186,108 pps, 4,276 sources, 0% fragments | UDP flood | 2 s | 3 s | 86.7% (92.9%) | 0.282% | 31.9% → 94.8% | 1.000 / 0.967 / 0.983 |
| pkt.UDP.rdm.fixedlength.pcapng | 4,968 pkts, 927 pps, 11 sources, 0% fragments | not detected | - s | - s | 0.0% (0.0%) | 0.000% | 100.0% → 100.0% | 1.000 / 0.000 / 0.000 |

## Rules ShieldWall wrote

- **amp.dns.RRSIG.fragmented.pcap**: none
- **amp.TCP.reflection.SYNACK.pcap**: RATE-LIMIT TCP SYN-ACK only from unknown sources to 100 pps
- **amp.UDP.isakmp.pcap**: RATE-LIMIT UDP from unknown sources to 606 pps
- **amp.UDP.snmp.src161.pcapng**: RATE-LIMIT UDP from unknown sources to 606 pps
- **pkt.UDP.rdm.fixedlength.pcapng**: none
