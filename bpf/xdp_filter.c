// SPDX-License-Identifier: GPL-2.0
/*
 * ShieldWall data plane: an XDP program that is small, fast and dumb on purpose.
 *
 * Runs on every packet, inside the NIC driver, before the kernel network stack.
 * Four jobs only:
 *   1. parse  eth -> ipv4 -> tcp/udp   (every access bounds-checked, or the verifier rejects us)
 *   2. count  totals, SYN/ACK, per-source, per-UDP-source-port into BPF maps
 *   3. check  the allowlist, then the rule maps written by the userspace controller
 *   4. drop   on a rule match (or rate-limit with a token bucket), otherwise pass
 *
 * It never decides whether there is an attack. Userspace reads the counters once a
 * second, detects, and writes rules back. The maps are the only bridge.
 *
 * Build:  clang -O2 -g -target bpf -c xdp_filter.c -o xdp_filter.o
 * Attach: ip link set dev eth0 xdpgeneric obj xdp_filter.o sec xdp   (or xdpdrv for native)
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ACTION_DROP       1
#define ACTION_RATE_LIMIT 2
#define RULE_SYN_ONLY      0x01
#define RULE_UNTRUSTED     0x02
#define RULE_FRAG          0x04   /* non-first IP fragments (no ports) */

/* ---- counters: kernel writes, userspace reads ----------------------------- */

struct counters {
	__u64 pkts;
	__u64 bytes;
	__u64 syn;
	__u64 ack;
	__u64 udp;
	__u64 tcp;
	__u64 dropped;
	__u64 allowlisted;
	__u64 frag;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct counters);
} stats SEC(".maps");

struct src_stat {
	__u64 pkts;
	__u64 bytes;
	__u64 syn;
	__u64 ack;
};

/* Per-source counts; userspace dumps and clears it every window and feeds the
 * sketches (Count-Min, HyperLogLog, Bloom). LRU so a spoofed flood cannot fill it. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);           /* IPv4 source, network order */
	__type(value, struct src_stat);
} src_count SEC(".maps");

/* UDP packets by SOURCE port: the amplification giveaway (53, 123, 389, 11211...). */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u16);
	__type(value, __u64);
} udp_sport_count SEC(".maps");

/* ---- rules: userspace writes, kernel reads -------------------------------- */

struct rule_key {
	__u8  proto;     /* IPPROTO_TCP / IPPROTO_UDP */
	__u8  flags;     /* RULE_SYN_ONLY | RULE_UNTRUSTED */
	__u16 sport;     /* host order, 0 = any */
	__u16 dport;     /* host order, 0 = any */
	__u16 pad;
};

struct rule_val {
	__u32 action;      /* ACTION_DROP / ACTION_RATE_LIMIT */
	__u32 rate_pps;    /* token refill rate for rate limits */
	__u64 tokens;      /* current bucket level, scaled by 1e9 (token-nanoseconds) */
	__u64 last_ns;
	__u64 expires_ns;  /* rules expire on their own; userspace renews while the attack lasts */
	__u64 hits;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);        /* rule cap: the controller can never flood itself */
	__type(key, struct rule_key);
	__type(value, struct rule_val);
} rules SEC(".maps");

struct lpm_v4 {
	__u32 prefixlen;
	__u32 addr;
};

/* Never drop these (admin, monitoring, upstream peers). */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_v4);
	__type(value, __u8);
} allowlist SEC(".maps");

/* Heavy hitters: single never-seen sources flooding the server; populated by userspace. */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_v4);
	__type(value, __u64);           /* drop counter */
} blocklist SEC(".maps");

/* Sources that completed handshakes in calm times; populated by userspace. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u8);
} trusted SEC(".maps");

/* config[0] = 1 -> enforce, 0 -> dry-run (count rule hits, drop nothing) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} config SEC(".maps");

/* ---- helpers --------------------------------------------------------------- */

static __always_inline int token_bucket_allow(struct rule_val *r, __u64 now)
{
	/* Approximate under concurrency (no lock); good enough for a rate limit. */
	__u64 elapsed = now - r->last_ns;
	__u64 cap = (__u64)r->rate_pps * 1000000000ULL;   /* one second of burst */
	__u64 tokens = r->tokens + elapsed * r->rate_pps;
	if (tokens > cap)
		tokens = cap;
	r->last_ns = now;
	if (tokens >= 1000000000ULL) {
		r->tokens = tokens - 1000000000ULL;
		return 1;
	}
	r->tokens = tokens;
	return 0;
}

static __always_inline struct rule_val *
lookup_rule(__u8 proto, __u16 sport, __u16 dport, int is_syn, int untrusted, int is_frag)
{
	struct rule_key k = { .proto = proto };
	struct rule_val *r;

	if (is_frag) {                       /* fragments carry no ports: only fragment rules apply */
		if (untrusted) {
			k.flags = RULE_FRAG | RULE_UNTRUSTED;
			r = bpf_map_lookup_elem(&rules, &k);
			if (r)
				return r;
		}
		k.flags = RULE_FRAG;
		return bpf_map_lookup_elem(&rules, &k);
	}

	/* Most specific first: signature on source port (amplification). */
	k.sport = sport;
	r = bpf_map_lookup_elem(&rules, &k);
	if (r)
		return r;
	k.sport = 0;
	k.dport = dport;
	r = bpf_map_lookup_elem(&rules, &k);
	if (r)
		return r;
	k.dport = 0;
	if (untrusted) {
		k.flags = RULE_UNTRUSTED | (is_syn ? RULE_SYN_ONLY : 0);
		r = bpf_map_lookup_elem(&rules, &k);
		if (r)
			return r;
		if (is_syn) {
			k.flags = RULE_UNTRUSTED;
			r = bpf_map_lookup_elem(&rules, &k);
			if (r)
				return r;
		}
	}
	if (is_syn) {
		k.flags = RULE_SYN_ONLY;
		r = bpf_map_lookup_elem(&rules, &k);
		if (r)
			return r;
	}
	return 0;
}

/* ---- the program ----------------------------------------------------------- */

SEC("xdp")
int shieldwall_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 zero = 0;
	__u64 len = data_end - data;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;                      /* IPv6 / ARP: out of scope for v1 */

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	if (ip->ihl < 5)
		return XDP_PASS;
	void *l4 = (void *)ip + ip->ihl * 4;
	int is_frag = (ip->frag_off & bpf_htons(0x1FFF)) != 0;   /* non-first fragment: no L4 header */

	__u16 sport = 0, dport = 0;
	int is_syn = 0, is_ack = 0;

	struct counters *c = bpf_map_lookup_elem(&stats, &zero);
	if (!c)
		return XDP_PASS;
	c->pkts++;
	c->bytes += len;

	if (is_frag && (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP)) {
		c->frag++;
		if (ip->protocol == IPPROTO_UDP)
			c->udp++;
		else
			c->tcp++;
	} else if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return XDP_PASS;
		sport = bpf_ntohs(tcp->source);
		dport = bpf_ntohs(tcp->dest);
		is_syn = tcp->syn && !tcp->ack;
		is_ack = tcp->ack;
		c->tcp++;
		if (is_syn)
			c->syn++;
		if (is_ack)
			c->ack++;
	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return XDP_PASS;
		sport = bpf_ntohs(udp->source);
		dport = bpf_ntohs(udp->dest);
		c->udp++;
		__u64 *n = bpf_map_lookup_elem(&udp_sport_count, &sport);
		if (n) {
			(*n)++;
		} else {
			__u64 one = 1;
			bpf_map_update_elem(&udp_sport_count, &sport, &one, BPF_ANY);
		}
	} else {
		return XDP_PASS;
	}

	/* per-source counters (count first, drop later: the detector must keep seeing the attack) */
	__u32 saddr = ip->saddr;
	struct src_stat *s = bpf_map_lookup_elem(&src_count, &saddr);
	if (s) {
		__sync_fetch_and_add(&s->pkts, 1);
		__sync_fetch_and_add(&s->bytes, len);
		if (is_syn)
			__sync_fetch_and_add(&s->syn, 1);
		if (is_ack)
			__sync_fetch_and_add(&s->ack, 1);
	} else {
		struct src_stat init = { .pkts = 1, .bytes = len, .syn = is_syn, .ack = is_ack };
		bpf_map_update_elem(&src_count, &saddr, &init, BPF_NOEXIST);
	}

	/* allowlist always wins */
	struct lpm_v4 lk = { .prefixlen = 32, .addr = saddr };
	if (bpf_map_lookup_elem(&allowlist, &lk)) {
		c->allowlisted++;
		return XDP_PASS;
	}

	/* heavy-hitter blocklist (any protocol) */
	__u64 *bl = bpf_map_lookup_elem(&blocklist, &lk);
	if (bl) {
		__sync_fetch_and_add(bl, 1);
		__u32 *enf = bpf_map_lookup_elem(&config, &zero);
		if (!enf || *enf) {
			c->dropped++;
			return XDP_DROP;
		}
	}

	int untrusted = bpf_map_lookup_elem(&trusted, &saddr) == 0;
	struct rule_val *r = lookup_rule(ip->protocol, sport, dport, is_syn, untrusted, is_frag);
	if (!r)
		return XDP_PASS;

	__u64 now = bpf_ktime_get_ns();
	if (r->expires_ns && now > r->expires_ns)
		return XDP_PASS;                      /* expired; userspace will delete it */

	int drop = 1;
	if (r->action == ACTION_RATE_LIMIT)
		drop = !token_bucket_allow(r, now);
	if (!drop)
		return XDP_PASS;

	__sync_fetch_and_add(&r->hits, 1);
	__u32 *enforce = bpf_map_lookup_elem(&config, &zero);
	if (enforce && *enforce == 0)
		return XDP_PASS;                      /* dry-run: log what we WOULD drop */
	c->dropped++;
	return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
