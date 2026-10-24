# LLM evaluation (gpt-4o-mini)

13 incident explanations from real engine runs + 8 chat questions over the event log, using the exact production prompts. Reproduce with `shieldwall llm-eval`.

| Metric | Result |
|---|---|
| Numeric grounding (numbers that match the facts) | 100.0% (61/61) |
| Explanations with zero hallucinated numbers | 100% |
| Names the correct attack / calls a surge legitimate | 100% |
| Chat answers correct | 100% |
| Claims judged supported, with the right meaning (LLM-as-judge) | 100% (79/79; misattributed 0, unsupported 0) |
| Explanations where every claim is supported | 100% |
| Rule suggestions accepted by the controller | 7/12 (all accepted ones start in dry-run) |
| Latency median / p95 | 1.5 s / 2.2 s |
| Tokens per call (in / out) | 674 / 128 |
| Cost per explanation | $0.00011 |
| Total cost of this evaluation | $0.0057 |

## Sample answers

- **cldap**: Your game server experienced a CLDAP amplification flood attack, peaking at 211,141 packets per second from 2,204 distinct sources. ShieldWall detected the attack in 2 seconds and began blocking it within 3 seconds, allowing 98.3% of real player traffic to get through. The incident is now resolved, and you do not need to take any further action.
- **dns**: Your server experienced a DNS amplification flood, with a peak of 162,053 packets per second from 2,435 distinct sources. ShieldWall detected the incident in 2 seconds and began mitigating it within 3 seconds, allowing 98.5% of real player traffic to get through. The incident is now resolved, and you do not need to take any action.
- **ntp**: Your server experienced an NTP amplification flood attack, peaking at 129,812 packets per second from 1,570 distinct sources. ShieldWall detected the attack within 2 seconds and began blocking it after 3 seconds, allowing 98.8% of real player traffic to get through. The incident is now resolved, and you do not need to take any action.
- **syn**: Your game server experienced a TCP SYN flood attack, with a peak of 159,402 packets per second from 2,490 distinct sources. ShieldWall detected the incident in 2 seconds and began blocking the attack traffic within 3 seconds, allowing 98.4% of real player traffic to get through. The incident is now resolved, and you do not need to take any action.
- **udp**: Your game server experienced a UDP flood attack with a peak of 131,378 packets per second from 2,479 distinct sources. ShieldWall detected the attack within 2 seconds and began blocking it after 3 seconds, allowing 99.1% of real player traffic to get through. The incident is now resolved, and no further action is needed on your part.
- **flash_crowd**: The server experienced a legitimate traffic surge with a peak of 7395 packets per second from 1882 distinct sources. ShieldWall detected the change in 3 seconds and confirmed that 100% of real player traffic got through during the incident. The incident is now resolved, and you do not need to take any action.
- **mega_cldap**: A CLDAP amplification flood attack is currently affecting your game server, with a peak of 936,014 packets per second coming from 2,170 distinct sources. ShieldWall detected the attack within 2 seconds and began mitigating it after 3 seconds, and while the incident is still ongoing, real player traffic is getting through normally again. You do not need to take any action at this time, as ShieldWall is actively blocking the attack traffic.

- **Q: Why did you block port 389?** Port 389 was blocked because your server was targeted by a CLDAP amplification flood attack. This attack involved UDP traffic from that port, and blocking it helped mitigate the threat.
- **Q: What attacks happened?** Two attacks occurred on your server:

1. A TCP SYN flood attack from about 2,468 sources, peaking at 158,720 packets per second. This incident lasted from 151 seconds to 182 seconds.
  
2. A CLDAP amplification flood attack from about 2,285 sources, peaking at 212,590 packets per second. This incident lasted from 41 seconds to 72 seconds.
- **Q: How many attacks were there?** There were two attacks: a TCP SYN flood and a CLDAP amplification flood.
- **Q: [report] cldap** ## Post-Incident Report: CLDAP Amplification Flood

The server experienced a CLDAP amplification flood attack, characterized by a high volume of UDP traffic originating from multiple sources, primarily using source port 389.

**Timeline**
- Incident detected at +2 seconds
- Mitigation rule applied at +3 seconds
- Current blocking in effect, incident still ongoing

**Impact:** The attack peaked at 208,793 packets per second, significantly affecting server performance, though real player traffic is currently getting through normally due to active blocking measures.

**Actions taken**
- Confirmed anomaly as CLDAP amplification flood
- Applied DROP rule for UDP traffic from source port 389

**Suggested rules (checked by the controller)**
- ✓ DROP UDP src port 389 from unknown sources: accepted in dry-run: matches 99% of the attack, 0.00% of normal traffic
- ✓ RATE-LIMIT UDP src port 389 from unknown sources to 1,000 pps: accepted in dry-run: matches 99% of the attack, 0.00% of normal traffic
- ✗ DROP UDP dst port 25565 from unknown sources: rejected: a drop on game port 25565 would lock out new players joining; only a rate limit is allowed there

- **Q: [report] dns** ## Post-Incident Report: DNS Amplification Flood

A DNS amplification flood attack was detected and mitigated on the Minecraft server, primarily targeting UDP traffic from source port 53.

**Timeline**
- 0s: Attack traffic begins
- 2s: Anomaly confirmed
- 3s: Mitigation rule applied to drop UDP traffic from source port 53

**Impact:** The attack peaked at 156,113 packets per second, overwhelming the server but allowing real player traffic to get through normally during mitigation efforts.

**Actions taken**
- Confirmed the anomaly as a DNS amplification flood
- Applied a rule to drop UDP traffic from source port 53
- Currently blocking attack traffic

**Suggested rules (checked by the controller)**
- ✓ DROP UDP src port 53 from unknown sources: accepted in dry-run: matches 99% of the attack, 0.00% of normal traffic
- ✓ RATE-LIMIT UDP src port 53 from unknown sources to 1,000 pps: accepted in dry-run: matches 99% of the attack, 0.00% of normal traffic

- **Q: [report] syn** ## Post-Incident Report: TCP SYN Flood

A TCP SYN flood attack was detected and mitigated on the Minecraft server, impacting connectivity for legitimate players.

**Timeline**
- 0s: Attack traffic begins
- 2s: Attack detected
- 3s: Mitigation rule applied
- Current: Attack ongoing, blocking in effect

**Impact:** The attack caused a significant increase in SYN packets, with a peak of 160,381 packets per second. 99% of packets originated from unknown sources, leading to potential connectivity issues for legitimate players, although real player traffic is currently getting through normally.

**Actions taken**
- Detected TCP SYN flood
- Applied rate-limit rule for TCP SYN from unknown sources

**Recommendations**
- Monitor traffic for any changes in patterns or new attack vectors.
- Consider implementing additional filtering rules to further mitigate SYN flood attacks.

**Suggested rules (checked by the controller)**
- ✗ DROP TCP dst port 25565 SYN only from unknown sources: rejected: a drop on game port 25565 would lock out new players joining; only a rate limit is allowed there
- ✓ RATE-LIMIT TCP dst port 25565 SYN only from unknown sources to 50 pps: accepted in dry-run: matches 99% of the attack, 0.11% of normal traffic

- **Q: [report] udp** ## Post-Incident Report: UDP Flood Attack

A UDP flood attack was detected and mitigated on the Minecraft server. The attack peaked at 128,510 packets per second with a significant percentage of traffic coming from unknown sources.

**Timeline**
- 0s: Attack traffic begins
- 2s: Anomaly confirmed
- 3s: Mitigation rule applied

**Impact:** The attack caused a significant increase in UDP traffic, with 98% of packets coming from unknown sources, impacting server performance.

**Actions taken**
- Confirmed the UDP flood attack
- Applied rate-limiting rule for UDP traffic from unknown sources

**Recommendations**
- Monitor traffic patterns for any new anomalies
- Consider implementing additional filtering rules to further mitigate unknown sources

**Suggested rules (checked by the controller)**
- ✗ DROP UDP dst port 25565 from unknown sources: rejected: a drop on game port 25565 would lock out new players joining; only a rate limit is allowed there
- ✗ DROP UDP dst port 19132 from unknown sources: rejected: a drop on game port 19132 would lock out new players joining; only a rate limit is allowed there
- ✗ RATE-LIMIT UDP from unknown sources to 1,000 pps: rejected: already in place

- **Q: [report] mega_cldap** ## Post-Incident Report: CLDAP Amplification Flood

A CLDAP amplification flood attack was detected and mitigated on the Minecraft server. The attack involved a high volume of UDP traffic from multiple sources, primarily using source port 389.

**Timeline**
- Incident detected at +2 seconds
- Mitigation rule applied at +3 seconds
- Escalation to upstream provider for filtering at +3 seconds

**Impact:** The attack peaked at 937,078 packets per second, affecting server performance but real player traffic was able to get through normally during the incident.

**Actions taken**
- Confirmed anomaly as CLDAP amplification flood
- Applied DROP rule for UDP source port 389
- Escalated to upstream provider for additional filtering

**Suggested rules (checked by the controller)**
- ✓ DROP UDP src port 389 from unknown sources: accepted in dry-run: matches 100% of the attack, 0.00% of normal traffic
- ✓ RATE-LIMIT UDP src port 389 from unknown sources to 1,000 pps: accepted in dry-run: matches 100% of the attack, 0.00% of normal traffic

