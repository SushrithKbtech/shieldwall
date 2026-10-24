# LLM evaluation (gpt-4o-mini)

13 incident explanations from real engine runs + 8 chat questions over the event log, using the exact production prompts. Reproduce with `shieldwall llm-eval`.

| Metric | Result |
|---|---|
| Numeric grounding (numbers that match the facts) | 100.0% (58/58) |
| Explanations with zero hallucinated numbers | 100% |
| Names the correct attack / calls a surge legitimate | 100% |
| Chat answers correct | 100% |
| Claims judged supported, with the right meaning (LLM-as-judge) | 92% (70/76; misattributed 5, unsupported 1) |
| Explanations where every claim is supported | 62% |
| Rule suggestions accepted by the controller | 0/15 (all accepted ones start in dry-run) |
| Latency median / p95 | 1.4 s / 1.8 s |
| Tokens per call (in / out) | 581 / 146 |
| Cost per explanation | $0.00010 |
| Total cost of this evaluation | $0.0056 |

## Sample answers

- **cldap**: Your game server experienced a CLDAP amplification flood, with a peak of 211,141 packets per second from 2,204 distinct sources. ShieldWall detected the issue within 2 seconds and began mitigation in 3 seconds, allowing 98.3% of real player traffic to get through without any significant impact on gameplay. No action is needed from you, as the incident has been resolved.
- **dns**: Your game server experienced a DNS amplification flood, peaking at 162,053 packets per second from 2,435 distinct sources. ShieldWall detected the issue in 2 seconds and began mitigating it within 3 seconds, allowing 98.5% of real player traffic to get through, so players were minimally affected. You do not need to take any action, as the incident has been resolved.
- **ntp**: Your game server experienced an NTP amplification flood, with a peak of 129,812 packets per second from 1,570 distinct sources. ShieldWall detected the issue within 2 seconds and began mitigating it in 3 seconds, allowing 98.8% of real player traffic to get through without interruption. You don't need to take any action, as the incident has been resolved.
- **syn**: Your game server experienced a TCP SYN flood attack, peaking at 159,402 packets per second from 2,490 distinct sources. ShieldWall detected the issue within 2 seconds and began mitigating it in 3 seconds, allowing 98.4% of real player traffic to get through without interruption. No action is needed from you, as the incident has been resolved.
- **udp**: Your game server experienced a UDP flood incident, peaking at 131,378 packets per second from 2,479 distinct sources. ShieldWall detected the issue within 2 seconds and began mitigating it in 3 seconds, allowing 99.1% of real player traffic to get through without any disruption. You don't need to take any action, as the incident has been resolved.
- **flash_crowd**: There was a legitimate surge in traffic on your game server, peaking at 7395 packets per second from 1882 distinct sources. ShieldWall detected this change within 3 seconds and confirmed that all traffic was legitimate, allowing 100% of real player traffic to get through without any blocks. You don't need to take any action, as the incident has been resolved.
- **mega_cldap**: Your game server experienced a CLDAP amplification flood, where 936,014 packets per second were sent from 2,170 distinct addresses. ShieldWall detected the issue within 2 seconds and began mitigation in 3 seconds, and while the flood exceeded your internet link, we escalated the situation to your provider for filtering. Currently, real player traffic is getting through normally, and you don’t need to take any action at this time.

- **Q: Why did you block port 389?** Port 389 was blocked because your server was targeted by a CLDAP amplification flood attack. This type of attack involves sending a large number of UDP packets from source port 389, which can overwhelm the server. By blocking this port, we aimed to prevent further malicious traffic from affecting your server.
- **Q: What attacks happened?** Two attacks occurred on your server:

1. A **TCP SYN flood** attack from about 2,468 sources, peaking at 158,720 packets per second. This attack lasted from 151 to 182 seconds.
2. A **CLDAP amplification flood** attack from about 2,285 sources, peaking at 212,590 packets per second. This attack lasted from 41 to 72 seconds.

Both attacks were mitigated by ShieldWall, allowing 98% of real player traffic to get through during the incidents.
- **Q: How many attacks were there?** There were two attacks on your server: a TCP SYN flood and a CLDAP amplification flood.
- **Q: [report] cldap** ## Post-Incident Report: CLDAP Amplification Flood

A CLDAP amplification flood attack was detected and mitigated on the Minecraft server, affecting UDP traffic primarily from source port 389.

**Timeline**
- Incident detected at +1s
- Anomaly confirmed at +1s
- Mitigation rule added at +1s
- Traffic mitigation took effect at +3s

**Impact:** The attack peaked at 208,793 packets per second, with 99% of the traffic being UDP from source port 389. The server experienced a significant influx of malicious traffic, but real player traffic was able to get through normally after mitigation was applied.

**Actions taken**
- Confirmed anomaly and identified the attack type
- Applied DROP rule for UDP traffic from source port 389

**Suggested rules (checked by the controller)**
- ✗ DROP UDP from 62.241.132.125: rejected: matches only 0.1% of the attack traffic
- ✗ DROP UDP from 91.153.4.214: rejected: matches only 0.1% of the attack traffic
- ✗ DROP UDP from 45.106.36.224: rejected: matches only 0.1% of the attack traffic

- **Q: [report] dns** ## Post-Incident Report: DNS Amplification Flood

The server experienced a DNS amplification flood attack, characterized by a high volume of UDP traffic originating from source port 53. The attack was confirmed within 2 seconds and mitigated within 3 seconds, allowing normal player traffic to resume shortly after.

**Timeline**
- 0s: Attack begins
- 1s: Anomaly confirmed: DNS amplification flood
- 2s: Rule added: DROP UDP src port 53
- 3s: Mitigation in place, normal traffic resumes

**Impact:** The attack peaked at 156,113 packets per second, with 99% of the traffic being UDP from source port 53. This resulted in a significant disruption, but real player traffic was able to get through normally after mitigation was applied.

**Actions taken**
- Confirmed the attack type as DNS amplification flood
- Applied a rule to drop UDP traffic from source port 53

**Suggested rules (checked by the controller)**
- ✗ DROP UDP from 8.151.248.72 src port 53: rejected: matches only 0.0% of the attack traffic
- ✗ DROP UDP from 199.221.222.69 src port 53: rejected: matches only 0.0% of the attack traffic
- ✗ DROP UDP from 138.172.83.196 src port 53: rejected: matches only 0.0% of the attack traffic

- **Q: [report] syn** ## Post-Incident Report: TCP SYN Flood Attack

A TCP SYN flood attack was detected and mitigated on the Minecraft server, impacting connectivity for a short duration.

**Timeline**
- Incident detected at 0s
- Anomaly confirmed at 1s
- Mitigation rule applied at 1s
- Peak attack observed at 2s
- Normal player traffic resumed at 3s

**Impact:** The attack peaked at 160,381 packets per second with 99% of packets originating from unknown sources. The server experienced a significant number of connection attempts that did not complete the handshake, but real player traffic was able to get through normally after mitigation was applied.

**Actions taken**
- Confirmed TCP SYN flood attack
- Applied rate-limit rule for TCP SYN from unknown sources to 100 pps

**Suggested rules (checked by the controller)**
- ✗ DROP TCP src port 35154 dst port 25565 SYN only from unknown sources: rejected: matches only 0.1% of the attack traffic
- ✗ DROP TCP src port 52344 dst port 25565 SYN only from unknown sources: rejected: matches only 0.1% of the attack traffic
- ✗ DROP TCP src port 13719 dst port 25565 SYN only from unknown sources: rejected: matches only 0.1% of the attack traffic

- **Q: [report] udp** ## Post-Incident Report: UDP Flood Attack

A UDP flood attack was detected on the Minecraft server, characterized by a significant increase in UDP traffic from numerous unknown sources.

**Timeline**
- 0s: Traffic normal
- 1s: Anomaly detected, UDP flood confirmed
- 2s: Rate-limit rule applied
- 3s: Mitigation in effect

**Impact:** The attack peaked at 128,510 packets per second, with 97% of packets originating from never-seen sources. The server experienced a significant disruption, but real player traffic is now getting through normally again.

**Actions taken**
- Confirmed anomaly as a UDP flood
- Applied rate-limit rule for UDP traffic from unknown sources

**Suggested rules (checked by the controller)**
- ✗ DROP UDP from 41.215.195.58: rejected: matches only 0.0% of the attack traffic
- ✗ DROP UDP from 177.178.203.23: rejected: matches only 0.0% of the attack traffic
- ✗ DROP UDP from 101.136.76.27: rejected: matches only 0.0% of the attack traffic

- **Q: [report] mega_cldap** ## Post-Incident Report: CLDAP Amplification Flood

A CLDAP amplification flood was detected and mitigated on the server, resulting in significant traffic disruption. The attack was confirmed to be malicious and involved a high volume of UDP packets from numerous distinct sources.

**Timeline**
- 0s: Traffic change detected
- 1s: Anomaly confirmed as CLDAP amplification flood
- 1s: Rule added to drop UDP traffic from source port 389
- 2s: Escalated to upstream provider for additional filtering
- 3s: Mitigation rule took effect

**Impact:** The server experienced a peak packet rate of 937,078 packets per second, overwhelming the internet link and leading to a request for upstream filtering. Real player traffic was temporarily affected but is now getting through normally again.

**Actions taken**
- Confirmed the anomaly as a CLDAP amplification flood
- Applied a rule to drop UDP traffic from source port 389
- Escalated the issue to the upstream provider for additional filtering

**Suggested rules (checked by the controller)**
- ✗ DROP UDP src port 389: rejected: already in place
- ✗ RATE-LIMIT UDP from 45.89.194.220 to 1,000 pps: rejected: matches only 0.1% of the attack traffic
- ✗ RATE-LIMIT UDP from 91.60.162.253 to 1,000 pps: rejected: matches only 0.1% of the attack traffic

