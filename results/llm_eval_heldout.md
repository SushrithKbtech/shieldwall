# LLM evaluation (gpt-4o-mini)

14 incident explanations from real engine runs + 8 chat questions over the event log, using the exact production prompts. Reproduce with `shieldwall llm-eval`.

| Metric | Result |
|---|---|
| Numeric grounding (numbers that match the facts) | 100.0% (66/66) |
| Explanations with zero hallucinated numbers | 100% |
| Names the correct attack / calls a surge legitimate | 100% |
| Chat answers correct | 100% |
| Claims judged supported, with the right meaning (LLM-as-judge) | 100% (89/89; misattributed 0, unsupported 0) |
| Explanations where every claim is supported | 100% |
| Rule suggestions accepted by the controller | 7/13 (all accepted ones start in dry-run) |
| Latency median / p95 | 1.5 s / 2.8 s |
| Tokens per call (in / out) | 663 / 131 |
| Cost per explanation | $0.00011 |
| Total cost of this evaluation | $0.0060 |

## Sample answers

- **cldap**: Your game server experienced a CLDAP amplification flood attack, peaking at 213,627 packets per second from 2,303 distinct sources. ShieldWall detected the attack within 2 seconds and began mitigating it in 3 seconds, allowing 98.4% of real player traffic to get through during the incident. The attack has now been resolved, and you do not need to take any action.
- **dns**: Your server experienced a DNS amplification flood attack, reaching a peak of 159,100 packets per second from 2,537 distinct sources. ShieldWall detected the attack within 2 seconds and began blocking it within 3 seconds, allowing 98.7% of real player traffic to get through. The incident is now resolved, and you do not need to take any action.
- **ntp**: Your server experienced an NTP amplification flood attack, peaking at 127,783 packets per second from 1,584 distinct sources. ShieldWall detected the attack within 2 seconds and began blocking it after 3 seconds, allowing 98.7% of real player traffic to get through. The incident is now resolved, and you do not need to take any further action.
- **syn**: Your game server experienced a TCP SYN flood attack with a peak of 159,426 packets per second from 2,501 distinct sources. ShieldWall detected the attack in 2 seconds and began blocking it within 3 seconds, allowing 98.4% of real player traffic to get through during the incident. The attack has been resolved, and you do not need to take any further action.
- **udp**: Your game server experienced a UDP flood attack, peaking at 127,998 packets per second from 2,413 distinct sources. ShieldWall detected the issue in 2 seconds and began mitigating it within 3 seconds, successfully allowing 98.4% of real player traffic through during the incident. The attack has now been resolved, and you do not need to take any further action.
- **flash_crowd**: There was a legitimate traffic surge on your game server, with a peak of 7205 packets per second from 1914 distinct sources. ShieldWall detected the change in 3 seconds and confirmed that 100% of real player traffic got through during the incident. The situation has been resolved, and you do not need to take any action.
- **mega_cldap**: Your game server is currently experiencing a CLDAP amplification flood, with a peak of 934,998 packets per second from 2,213 distinct sources. ShieldWall detected the issue in 2 seconds and began mitigating it in 3 seconds, and while the incident is still ongoing, real player traffic is getting through normally again. You do not need to take any action at this time, as ShieldWall is actively blocking the attack traffic.

- **Q: Why did you block port 389?** Port 389 was blocked because there was a CLDAP amplification flood attack. This attack involved malicious traffic using UDP from source port 389, which your server never sends CLDAP queries for, indicating that these were reflected replies. Blocking this port helped mitigate the attack.
- **Q: What attacks happened?** Two attacks occurred on your server:

1. A TCP SYN flood attack from about 2,479 sources, peaking at 159,531 packets per second. This attack started at 151 seconds and ended at 182 seconds.
   
2. A CLDAP amplification flood attack from about 2,195 sources, peaking at 213,725 packets per second. This attack started at 41 seconds and ended at 72 seconds.
- **Q: How many attacks were there?** There were two attacks: a TCP SYN flood and a CLDAP amplification flood.
- **Q: [report] cldap** ## Post-Incident Report: CLDAP Amplification Flood

The server experienced a CLDAP amplification flood attack, characterized by a significant increase in UDP traffic from multiple sources, primarily using source port 389.

**Timeline**
- 0s: Attack traffic begins
- 2s: Anomaly detected and confirmed
- 3s: Mitigation rule applied to drop UDP traffic from source port 389

**Impact:** The attack peaked at 211,426 packets per second, overwhelming the server's capacity. However, real player traffic was able to get through normally after mitigation was applied.

**Actions taken**
- Confirmed the attack type as CLDAP amplification flood
- Applied a rule to drop UDP traffic from source port 389

**Suggested rules (checked by the controller)**
- ✓ DROP UDP src port 389 from unknown sources: accepted in dry-run: matches 99% of the attack, 0.00% of normal traffic
- ✓ RATE-LIMIT UDP src port 389 from unknown sources to 1,000 pps: accepted in dry-run: matches 99% of the attack, 0.00% of normal traffic
- ✗ DROP UDP dst port 25565 from unknown sources: rejected: a drop on game port 25565 would lock out new players joining; only a rate limit is allowed there

- **Q: [report] dns** ## Post-Incident Report: DNS Amplification Flood

A DNS amplification flood attack was detected and mitigated on the Minecraft server, resulting in a significant volume of unwanted traffic.

**Timeline**
- 0s: Attack traffic begins
- 2s: Anomaly confirmed
- 3s: Mitigation rule applied to drop UDP traffic from source port 53

**Impact:** The attack peaked at 158,165 packets per second, overwhelming the server's capacity. However, real player traffic was able to get through normally after mitigation was applied.

**Actions taken**
- Confirmed the anomaly as a DNS amplification flood
- Applied a rule to drop UDP traffic from source port 53

**Suggested rules (checked by the controller)**
- ✓ DROP UDP src port 53 from unknown sources: accepted in dry-run: matches 99% of the attack, 0.00% of normal traffic
- ✓ RATE-LIMIT UDP src port 53 from unknown sources to 100 pps: accepted in dry-run: matches 99% of the attack, 0.00% of normal traffic

- **Q: [report] syn** ## Post-Incident Report: TCP SYN Flood Attack

A TCP SYN flood attack was detected and mitigated on the Minecraft server, impacting normal traffic flow. The attack involved a high volume of SYN packets from a large number of distinct sources, overwhelming the server's ability to process legitimate connections.

**Timeline**
- Incident detected: 0s
- Anomaly confirmed: 1s
- Mitigation rule applied: 1s
- Blocking initiated: 3s

**Impact:** The attack peaked at 159,214 packets per second, with 99% of packets originating from never-seen sources. Real player traffic was affected but is currently getting through normally after mitigation was applied.

**Actions taken**
- Confirmed TCP SYN flood attack
- Applied rate-limit rule for TCP SYN packets from unknown sources to 100 pps
- Blocked attack traffic

**Suggested rules (checked by the controller)**
- ✗ DROP TCP dst port 25565 SYN only from unknown sources: rejected: a drop on game port 25565 would lock out new players joining; only a rate limit is allowed there
- ✓ RATE-LIMIT TCP dst port 25565 SYN only from unknown sources to 50 pps: accepted in dry-run: matches 99% of the attack, 0.24% of normal traffic
- ✗ DROP TCP src port 49503 dst port 25565 SYN only: rejected: a drop on game port 25565 would lock out new players joining; only a rate limit is allowed there

- **Q: [report] udp** ## Post-Incident Report: UDP Flood Attack

A UDP flood attack was detected and mitigated on the Minecraft server, impacting normal traffic flow.

**Timeline**
- 0s: Attack traffic begins
- 2s: Anomaly confirmed as UDP flood
- 3s: Rate-limit rule applied to unknown sources

**Impact:** The attack peaked at 125,134 packets per second, with 98% of the packets coming from never-seen sources, severely affecting server performance.

**Actions taken**
- Confirmed UDP flood attack
- Applied rate-limit rule for UDP from unknown sources to 604 pps

**Suggested rules (checked by the controller)**
- ✗ DROP UDP dst port 19132 from unknown sources: rejected: a drop on game port 19132 would lock out new players joining; only a rate limit is allowed there
- ✗ DROP UDP dst port 25565 from unknown sources: rejected: a drop on game port 25565 would lock out new players joining; only a rate limit is allowed there
- ✗ RATE-LIMIT UDP dst port 19132 from unknown sources to 1,000 pps: rejected: matches only 0.0% of the attack traffic

- **Q: [report] mega_cldap** ## Post-Incident Report: CLDAP Amplification Flood

A CLDAP amplification flood attack was detected and mitigated on the Minecraft server. The attack involved a significant volume of UDP traffic from multiple sources, primarily using source port 389.

**Timeline**
- 0s: Attack traffic begins
- 2s: Anomaly confirmed
- 3s: Mitigation rule applied to drop UDP traffic from source port 389
- 3s: Escalated to upstream provider for additional filtering

**Impact:** The attack peaked at 935,685 packets per second, overwhelming the server's capacity. However, real player traffic was able to get through normally during the incident due to prompt mitigation actions.

**Actions taken**
- Confirmed anomaly and identified attack type
- Applied mitigation rule to drop UDP traffic from source port 389
- Escalated to upstream provider for additional filtering

**Suggested rules (checked by the controller)**
- ✓ DROP UDP src port 389 from unknown sources: accepted in dry-run: matches 100% of the attack, 0.00% of normal traffic
- ✓ RATE-LIMIT UDP src port 389 from unknown sources to 1,000 pps: accepted in dry-run: matches 100% of the attack, 0.00% of normal traffic

