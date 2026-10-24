# Replay of real DDoS captures

Real attack packets (sources, ports, sizes, flags, fragments) from public captures, replayed at their own packet rate for 30 s on top of modelled player traffic (~2,000 pps). Ground truth = which packets came from the capture. Captures: github.com/StopDDoS/packet-captures ("packet captures of real-world ddos attacks"). Reproduce with `shieldwall replay <file.pcap>`.

| Capture | What is in it | Classified as | Detect | Block | Attack dropped: whole attack (once blocking) | Real traffic dropped | Players served (without → with) | Precision / recall / F1 (per second) |
|---|---|---|---|---|---|---|---|---|
| amp.UDP.DNSANY.pcap | 11,998 pkts, 20,889 pps, 79 sources, 24% fragments | DNS amplification flood | 2 s | 3 s | 91.9% (98.5%) | 0.000% | 100.0% → 100.0% | 1.000 / 0.967 / 0.983 |
| pkt.TCP.synflood.spoofed.pcap | 37,841 pkts, 1,598 pps, 37,623 sources, 0% fragments | TCP SYN flood | 2 s | 3 s | 87.5% (93.8%) | 0.061% | 100.0% → 99.8% | 1.000 / 0.967 / 0.983 |
| amp.UDP.memcached.ntp.cldap.pcap | 29,462 pkts, 103,484 pps, 1,992 sources, 14% fragments | multi-vector amplification (Memcached, NTP, DNS) | 2 s | 3 s | 92.5% (99.1%) | 0.000% | 56.9% → 97.3% | 1.000 / 0.967 / 0.983 |

## Rules ShieldWall wrote

- **amp.UDP.DNSANY.pcap**: DROP UDP src port 53; DROP UDP fragments from unknown sources
- **pkt.TCP.synflood.spoofed.pcap**: RATE-LIMIT TCP SYN only from unknown sources to 100 pps
- **amp.UDP.memcached.ntp.cldap.pcap**: DROP UDP src port 11211; DROP UDP src port 123; DROP UDP src port 53; DROP UDP src port 389; DROP UDP fragments from unknown sources
