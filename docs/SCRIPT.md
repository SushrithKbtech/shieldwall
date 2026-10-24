# ShieldWall: progress presentation script

Two speakers, about 7 minutes plus questions. **A** and **B** take turns. Simple words on purpose: say it like you're explaining to a friend, not reading a paper.

Before you start: run `shieldwall dashboard`, open http://127.0.0.1:8000, and wait 20 seconds so the graph has a flat "normal" line.

---

## 1. The problem (A, ~1 min)

**A:** Imagine you run a small Minecraft server for your friends. One day someone pays about 38 dollars an hour to a DDoS-for-hire service. Thousands of hacked devices start sending junk traffic to your server at the same time. Your server can't tell real players from junk, it gets overloaded, and everyone gets kicked.

**A:** This is really common. Gaming is the most attacked industry, about 37% of all DDoS attacks. Big companies buy protection from Cloudflare. A student or a small server owner can't afford that and doesn't know what to do. That gap is who we're building for.

## 2. Our idea in one line (B, ~30 s)

**B:** ShieldWall is a smart bouncer that sits in front of a small server. It does three things: it **detects** an attack in seconds, it **blocks** the bad traffic while real players keep playing, and it **explains** what happened in plain English.

**B:** And one honest limit we always say upfront: if the attack is bigger than the server's internet connection, no software on that server can fix it. For that case we ask the internet provider upstream to filter it, and I'll show that later.

## 3. How it works (A, ~1.5 min)

**A:** The main idea is two halves running on two different clocks.

**A:** The first half lives inside the Linux kernel, using a technology called eBPF and XDP. It runs on every single packet, before the computer does any real work on it. Its job is tiny: look at the packet, add to some counters, and if there's a rule saying "drop this", drop it. That's it. It's fast because it doesn't think.

**A:** The second half runs once every second in normal Python. It reads those counters, decides if there's an attack, figures out what kind, and writes a blocking rule back down to the kernel.

**A:** The two halves only talk through shared tables called BPF maps. So: the cheap work, counting and dropping, happens in the kernel. The hard thinking happens in safe userspace. That's the same design big protection companies use.

## 4. The detection maths (B, ~1.5 min)

**B:** We don't use a fixed rule like "alert above 10,000 packets per second", because that's wrong at 3 a.m. and wrong again at peak time. Instead three methods vote.

**B:** One: we learn what normal looks like with a moving average, and measure how far we are from it in standard deviations. That's a z-score. Normal is within about 3. An attack is often over 1,000.

**B:** Two: CUSUM. It adds up small increases over time, so it catches an attack that ramps up slowly.

**B:** Three: entropy, which measures how spread out the sources are. A botnet suddenly spreads traffic across thousands of new addresses, so entropy jumps.

**B:** We only alert if at least two agree, it lasts at least two seconds, and the jump is big in absolute terms. That keeps false alarms down.

**B:** To track millions of addresses in tiny memory we use three classic data structures: a Count-Min Sketch to find the top senders, a HyperLogLog to count unique sources in 1 KB, and a Bloom filter to remember who we've seen before.

## 5. Live demo (A drives, B narrates, ~2 min)

**A:** *(points at the dashboard)* This is normal traffic, about 2,000 packets per second of players. The dotted line is the baseline it learned by itself.

**A:** *(click **CLDAP amplification**)* I've just started an attack in our isolated lab: 200,000 packets per second.

**B:** Watch the red line jump. In about 2 seconds all three detector boxes light up, and it says "CLDAP amplification flood". It knows the type because the traffic comes from port 389, and our server never uses that service. That's the giveaway for amplification attacks.

**B:** Now look at the green line, traffic actually reaching the server. It drops back to normal. A rule "DROP UDP src port 389" appeared on the right. And the player success graph went back to 100%.

**A:** And here's the AI panel. *(read the explanation out loud)* We can also ask it: *(type "why did you block port 389?")*

**B:** Important point: the AI only explains. The blocking decision is made by the maths in milliseconds. An LLM is too slow and unpredictable to decide what to block, so we never let it.

**A:** *(click **Flash crowd**)* Now a different case: lots of real players join at once, like a launch day. Traffic triples.

**B:** It notices the jump, but says "legitimate traffic surge" and blocks nobody, because the connections complete normally and the traffic mix looks like real players. Not punishing your own users is the hardest part of this problem.

**A:** *(optional, click **Bigger than the link**)* Last one: a 25 Gbps attack into a 10 Gbps connection. The pipe is full before we can do anything locally, so ShieldWall sends the rule upstream as a BGP FlowSpec rule, and players recover.

## 6. Results (B, ~45 s)

**B:** We tested four scenarios automatically, each with and without ShieldWall on the same traffic.

**B:** Without it, real players got 30 to 50% of their traffic through during an attack. With it, 98 to 99%. Detection takes 2 seconds and blocking 3 seconds. In the flash-crowd test it added zero rules and dropped zero real traffic. Even the bigger-than-the-link attack recovered to about 96% once the upstream filter kicked in.

**B:** We also measured accuracy, precision, recall and F1 over 60 random trials with weak and strong attacks, flash crowds and quiet periods. *(read the numbers from the results slide)* The attack traffic in these tests comes from our lab traffic generator, so we know exactly when each attack happened.

## 7. Wrap-up (A, ~45 s)

**A:** What we built: the kernel XDP program in C, the detection engine with the three voting methods and three data structures, a classifier for five attack types, mitigation with expiring rules and safety limits, upstream escalation, the AI explainer, the SQLite log, this dashboard, and a test harness.

**A:** And it runs on a real kernel. Our kernel test loads the XDP program on a Linux network interface, replays a CLDAP flood from 500 sources, and the kernel dropped all 3,000 attack packets while all 400 player packets went through.

**B:** So in one line: a smart bouncer for small servers that blocks attacks by itself and explains what it did. The code is on GitHub. Thank you, happy to take questions.

---

## Likely questions (both, short answers)

**Why not just use a firewall like iptables?**
iptables runs after the kernel has already done a lot of work on the packet. XDP runs before that, so it can drop millions of packets per second on one core. And iptables doesn't detect anything; it only enforces rules someone wrote by hand.

**Why not machine learning?**
Statistics are transparent: we can always say exactly why it fired. ML models trained on one dataset often fail on another. We plan to show that as an experiment instead of claiming a high accuracy number.

**What if the attacker uses the same port as real players?**
That's the SYN and UDP flood cases. Then we can't use a clean signature, so we rate-limit sources we've never seen complete a normal connection, while known players pass through.

**What if an attacker poisons the baseline by ramping up slowly?**
CUSUM is built for exactly that, and the baseline freezes the moment the methods start disagreeing with normal.

**Can ShieldWall block real users by mistake?**
Three protections: the flash-crowd check, an allowlist that is never dropped, and every rule expires after 60 seconds unless the attack is still going. There's also a dry-run mode that only logs what it would drop.

**Why is the LLM there at all?**
The person we're building for isn't a network engineer. "CLDAP 2.1 Mpps from 1,840 sources" means nothing to them. "You were attacked, I blocked it in 3 seconds, players are fine" does.

**Is the demo traffic real?**
The dashboard uses our lab traffic generator, which models players, attackers, the internet link and the server's capacity. Separately, our kernel test sends real packets through the real XDP program on Linux.

**What are precision and recall here?**
Precision: when ShieldWall says "attack", how often it really is one. Recall: of all real attack seconds, how many it caught. F1 balances the two. We test against ground truth because the lab knows exactly when each attack ran.

**Is it legal to generate attack traffic?**
Only inside an isolated lab we own, with no route to the internet. We never use stresser services or target anything we don't own.

---

## Who knows what (so you can both answer anything)

| Topic | Lead | Backup |
|---|---|---|
| Problem, architecture, XDP | A | B |
| Detection maths, sketches | B | A |
| Demo | A drives | B narrates |
| Results, limits | B | A |
| Roadmap | A | B |
