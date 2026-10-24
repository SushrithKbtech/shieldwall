# Replay of CIC-DDoS2019 flow records

CIC-DDoS2019 (CSV release, CICFlowMeter flow records). For each file, the busiest 30 s of attack flows to the victim are rebuilt into a packet stream (real addresses, ports, protocol, packet counts, sizes and timing per flow; packet spacing inside a flow is approximated) and replayed at the true packet rate on top of modelled player traffic. Ground truth = the dataset's own attack labels. Reproduce with `shieldwall replay-cic archive.zip --member 01-12/Syn.csv`.

| Capture | What is in it | Classified as | Detect | Block | Attack dropped: whole attack (once blocking) | Real traffic dropped | Players served (without → with) | Precision / recall / F1 (per second) |
|---|---|---|---|---|---|---|---|---|
| archive.zip:01-12/Syn.csv | 1,225,604 pkts, 40,853 pps, 1 sources, 0% fragments | flood from a single host (172.16.0.5) | 2 s | 3 s | 93.3% (100.0%) | 0.000% | 100.0% → 100.0% | 1.000 / 0.967 / 0.983 |
| archive.zip:01-12/DrDoS_NTP.csv | 6,443,149 pkts, 214,772 pps, 1 sources, 0% fragments | flood from a single host (172.16.0.5) | 2 s | 3 s | 93.3% (100.0%) | 0.000% | 27.7% → 95.5% | 1.000 / 0.967 / 0.983 |
| archive.zip:01-12/DrDoS_LDAP.csv | 579,270 pkts, 19,309 pps, 1 sources, 0% fragments | flood from a single host (172.16.0.5) | 2 s | 3 s | 93.3% (100.0%) | 0.000% | 100.0% → 100.0% | 1.000 / 0.967 / 0.983 |

## Rules ShieldWall wrote

- **archive.zip:01-12/Syn.csv**: DROP ALL from 172.16.0.5
- **archive.zip:01-12/DrDoS_NTP.csv**: DROP ALL from 172.16.0.5
- **archive.zip:01-12/DrDoS_LDAP.csv**: DROP ALL from 172.16.0.5
