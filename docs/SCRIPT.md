# ShieldWall: presentation script (Team RSST)

Four speakers, about 8 minutes plus questions. Simple words on purpose: say it like you're explaining to a friend.

| Speaker | Sections | Owns in the viva |
|---|---|---|
| **Rohit** | 1. Problem, 2. Idea | the problem, the dashboard, the demo |
| **Saran** | 3. Design and the kernel | the XDP program, BPF maps, the real-kernel test |
| **Sushrith** | 4. Detection, 6. Results | the detection maths, classifier, real-data replay |
| **Tamish** | 5. Live demo with mitigation and AI, 7. Wrap-up | mitigation rules, the LLM layer and its evaluation |

Swap roles if you prefer, but everyone should be able to answer the "Likely questions" at the end.

Before you start: run `shieldwall dashboard`, open http://127.0.0.1:8000, wait 20 seconds so the graph has a flat "normal" line.

---

## 1. The problem (Rohit, ~1 min)

**Rohit:** Imagine you run a small Minecraft server for your friends. Someone pays about 38 dollars an hour to a DDoS-for-hire service, and thousands of machines flood your server with junk. It can't tell real players from junk, it overloads, and everyone gets kicked.

**Rohit:** Gaming is the most attacked industry, about 37% of all DDoS attacks. Big companies buy Cloudflare. A student or a small server owner can't, and has nothing automatic. That's who we built this for.

## 2. Our idea in one line (Rohit, ~30 s)

**Rohit:** ShieldWall is a smart bouncer in front of a small server. It **detects** an attack in about 2 seconds, **blocks** the bad traffic while real players keep playing, and **explains** what happened in plain English.

**Rohit:** One honest limit: if the attack is bigger than the server's internet connection, nothing on the server can fix that. It needs the internet provider upstream. We show that escalation in our simulator.

## 3. Design and the kernel (Saran, ~1.5 min)

**Saran:** Two halves on two clocks. The first half lives inside the Linux kernel, using eBPF and XDP. It runs on every packet before the computer does any real work on it. Its job is tiny: count the packet, and drop it if a rule says so.

**Saran:** The second half is Python, once a second. It reads the counters, decides if there's an attack and what kind, and writes a blocking rule back into the kernel. The two halves only talk through shared tables called BPF maps.

**Saran:** And this runs on a real kernel. Our kernel test loads the program on a Linux network interface and sends real packets. The kernel dropped 3,000 of 3,000 attack packets and let all 400 player packets through. It also dropped 1,000 of 1,000 IP fragments, and every packet from a blocked flooding host, including pings, while other traffic passed. Blocked addresses expire inside the kernel, so nothing stays blocked if the controller crashes. And we replayed real attack captures through it: the live loop recognised them in 2 seconds and the kernel dropped about 99% of their packets.

## 4. Detection (Sushrith, ~1.5 min)

**Sushrith:** No fixed thresholds like "alert above 10,000 packets". Three alarms vote. *(open the **How it works** tab)*

**Sushrith:** A spike alarm compares traffic with a running average of normal. A build-up alarm adds up small rises, so it catches slow attacks. A stranger alarm measures how spread out the senders are. We alert only if two agree, for two seconds, and the jump is big. Then a fingerprint check names the attack: traffic *from* port 389 means CLDAP amplification, SYNs without ACKs means a SYN flood, and one never-seen address sending most of the traffic means a single-host flood.

**Sushrith:** No training was needed. It learns each server's normal traffic live in about 10 seconds.

## 5. Live demo: blocking and the AI (Tamish, ~2 min)

**Tamish:** *(back to **Live monitor**, click **CLDAP amplification**)* The banner turns red: "Under attack: CLDAP amplification flood." The three alarms light up, and the steps move to Detected, Identified and Blocked. Under "What is being blocked" it says "Dropping UDP traffic coming from port 389". Players are back to 100%.

**Tamish:** The AI assistant is gpt-4o-mini. *(read the explanation)* It only sees verified facts, and it never decides what to block. *(click **Write incident report + suggest rules**)* It writes a report and suggests extra rules. ShieldWall's controller then tests every suggestion against real traffic and rejects anything unsafe or useless. Accepted rules start in dry-run, so the AI can never block anything by itself.

**Tamish:** *(click **Flash crowd**)* Lots of real players join at once. The banner turns yellow, "Busy, but it's real players", and nobody is blocked.

## 6. Results (Sushrith, ~1.5 min)

**Sushrith:** *(open **Results**)* Three kinds of evidence, and we're careful to say which is which.

**Sushrith:** First, **real attack data that we didn't create**. Three public captures of real-world attacks, and three attacks from the CIC-DDoS2019 university dataset, replayed through the engine. All 6 were detected in about 2 seconds and blocked within 3 seconds; once blocking started, at least 93.7% of attack packets were dropped, with zero false alarms. Then we sent two of the real captures through the real XDP program on Linux: the kernel dropped 98.5% and 99.1% of their packets, and not a single player packet.

**Sushrith:** Testing on real data found real problems, and we fixed them. Real amplification floods are partly IP fragments with no port numbers, so a port rule let them through. One capture mixed three attack types at once. And CIC-DDoS2019's attacks all come from a single machine, which our fingerprints missed until we added a heavy-hitter rule. That's the value of testing on data you didn't write. But because we fixed things using those files, we also froze the code and ran it once on eight attacks nobody had looked at. It caught 5 of 8. Two were too small to matter, and one, a TCP SYN-ACK reflection attack, was a real miss: the alarms fired but no fingerprint matched, and we deliberately don't block what we can't classify. We'd rather show you that than a perfect score.

**Sushrith:** Second, **our simulated lab**, where we know the exact right answer for every second: 200 random trials, half attacks and half not. Precision was 100%, so it never once called normal traffic an attack: 0 of 93 non-attacks were blocked. F1 was 0.97 per second and 0.99 per attack.

**Sushrith:** Third, **the AI itself**. An automatic check confirmed every number gpt-4o-mini wrote matches the facts, and the same model, prompted as a strict fact-checker, judged whether each claim used the number with the right meaning. That's a check, not proof. 100% of its numbers matched the facts. The judge first rated 92% of claims faithful because the model over-claimed, so we fixed the prompt using what the evaluation found. On new incidents the prompt was never tuned on, 89 of 89 claims were judged faithful and 7 of its 13 suggested rules passed the controller. Each explanation costs about $0.0001.

## 7. Wrap-up (Tamish, ~30 s)

**Tamish:** So: a kernel filter that's tested on a real Linux kernel, a detection engine tested on real attack data, and an AI that explains and suggests but never blocks, and which we evaluated. In one line: a smart bouncer for small servers that blocks attacks by itself and explains what it did. The code is on GitHub. Thank you.

---

## Likely questions (everyone, short answers)

**Isn't testing on your own simulator circular?**
That's why we also replayed real attack captures and CIC-DDoS2019 attacks we didn't create. The real data exposed three weaknesses (fragments, multi-vector attacks, single-host floods), which we fixed.

**Is the CIC-DDoS2019 test real packets?**
The CSV release only has flow records. We rebuilt packets from them: real addresses, ports, protocols, packet counts, sizes and timing per flow. Only the spacing of packets inside a flow is approximated. CIC can't test the attack-type checks: every attack comes from one machine, the "NTP" and "LDAP" attacks don't use ports 123 and 389, and the "Syn" flows rebuild with no SYN flags. So CIC tests the single-host rule; the public captures test the fingerprints.

**Did you tune on the same data you report?**
Partly, and we say so: fixing what real data exposed changed thresholds and added rules. That's why we also froze the code and ran it once on data nobody had looked at: five more public captures, three more CIC-DDoS2019 files, and the LLM on new incidents. Those held-out numbers are reported separately.

**What if many real players share one IP (a college network or a mobile carrier)?**
If one new address sends most of the traffic and that traffic goes to the game's own ports, ShieldWall rate-limits it to a fair share instead of blocking it, so those players keep playing. Only a single host that isn't talking to the game gets blocked outright.

**Can an attacker get its bots trusted first?**
It's harder now: a source is only trusted after it has been seen in 5 separate calm seconds, not one burst. A patient attacker could still pre-warm bots, which is why trust only relaxes rate limits; amplification and fragment rules apply to everyone.

**Did you train anything? Why not machine learning?**
No training: it learns each server's normal traffic live. Statistics are explainable, which lets the LLM say exactly why it fired, and they adapt when traffic changes. ML trained on one dataset often fails on another network.

**Where is the LLM work?**
Grounded prompting (verified facts with their meanings), keeping it off the blocking path, structured incident reports, rule suggestions validated by the controller, and an evaluation: a hallucinated-number check, an LLM-as-judge faithfulness check, chat accuracy, latency and cost.

**Can the AI block real players by mistake?**
No. It can only suggest. The controller rejects any rule that would hit more than 1% of recent player traffic, and accepted rules start in dry-run.

**Is the FlowSpec / upstream part real?**
No, it's simulated. The tool writes the rule an ISP would need, and our simulator plays the ISP. A real BGP setup would be the next step.

**Why not just iptables?**
iptables runs after the kernel has done a lot of work per packet; XDP runs before that, so it can drop millions of packets per second on one core. And iptables doesn't detect anything.

**What can't it do?**
Floods bigger than the link need the provider. IPv4 only. Website-request (HTTP) floods aren't classified. We haven't measured raw throughput (packets per second per core) yet; that needs a Linux machine or VM whose network driver supports native XDP, which most cloud VMs have.
