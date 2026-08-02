#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#endif

#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

// Statistics Map
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 10);
  __type(key, __u32);
  __type(value, __u64);
} stats_map SEC(".maps");

// Stat IDs
#define STAT_GEO_DROP 0
#define STAT_RATE_LIMIT_DROP 1
#define STAT_TCP_INVALID 2
#define STAT_UDP_INVALID 3
#define STAT_GLOBAL_UDP_DROP 4

static __always_inline void record_stat(__u32 stat_id) {
  __u64 *value = bpf_map_lookup_elem(&stats_map, &stat_id);
  if (value) {
    *value += 1;
  }
}

struct config_data {
  __u32 rate_limit_pps;
  __u32 global_udp_pps;
  __u32 sni_filtering;
  __u32 strict_tcp_tracking;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct config_data);
} config_map SEC(".maps");

struct rate_value {
  __u64 last_epoch;
  __u64 count;
  __u64 syn_count;
};

// Rate Limit Map
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 100000);
  __type(key, __u32);
  __type(value, struct rate_value);
} rate_limit_map SEC(".maps");

// IP Spoofing Bloom Filter Map
struct {
  __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
  __uint(max_entries, 1000000);
  __type(value, __u32);
} ip_bloom_map SEC(".maps");

// Global UDP Rate Limit Map
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct rate_value);
} global_udp_rate_map SEC(".maps");

// Port-Specific UDP Rate Limit Map
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 65536);
  __type(key, __u32);
  __type(value, struct rate_value);
} port_udp_rate_map SEC(".maps");

// Allowed Ports Map (Fast-Path O(1) Lookup)
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 65536);
  __type(key, __u32);
  __type(value, __u8);
} allowed_ports_map SEC(".maps");

// Geo-Blocking LPM Trie Map
struct ipv4_lpm_key {
  __u32 prefixlen;
  __u32 ipv4;
};

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 500000);
  __type(key, struct ipv4_lpm_key);
  __type(value, __u8);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} geo_map SEC(".maps");

// SNI Map
struct nat_key {
  __be32 public_ip;
  __be16 public_port;
  __u16 protocol;
};

struct nat_value {
  __be32 internal_ip;
  __be16 internal_port;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct nat_key);
  __type(value, struct nat_value);
} nat_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, __u64);  // FNV-1a hash
  __type(value, __u8); // 1 = allowed
} sni_map SEC(".maps");

static __always_inline __u64 parse_tls_sni(void *payload, void *data_end_void) {
  __u8 *ptr = payload;
  __u8 *data_end = data_end_void;

  // Sentinel return values:
  // 0                  = not TLS / not ClientHello (pass through)
  // 0xFFFFFFFFFFFFFFFF = error/truncated/no SNI found (drop when SNI filtering
  // enabled) any other value    = valid FNV-1a SNI hash (check against
  // whitelist)
  if (ptr + 44 > data_end)
    return 0;

  if (ptr[0] != 0x16)
    return 0;
  if (ptr[5] != 0x01)
    return 0;

  __u32 offset = 44;
  __u32 session_id_len = ptr[43];
  offset += session_id_len;
  offset &= 0x1FFF;

  if (ptr + offset + 2 > data_end)
    return 0xFFFFFFFFFFFFFFFFULL;
  __u32 cipher_suites_len = (ptr[offset] << 8) | ptr[offset + 1];

  offset += 2 + cipher_suites_len;
  offset &= 0x1FFF;

  if (ptr + offset + 1 > data_end)
    return 0xFFFFFFFFFFFFFFFFULL;
  __u32 comp_methods_len = ptr[offset];

  offset += 1 + comp_methods_len;
  offset &= 0x1FFF;

  if (ptr + offset + 2 > data_end)
    return 0xFFFFFFFFFFFFFFFFULL;
  offset += 2;
  offset &= 0x1FFF;

  // Scan up to 20 extensions to avoid false-dropping clients with many
  // extensions
  for (int i = 0; i < 20; i++) {
    offset &= 0x1FFF; // Force verifier to cap range
    if (ptr + offset + 4 > data_end)
      break;
    __u16 ext_type = (ptr[offset] << 8) | ptr[offset + 1];
    __u32 ext_len = (ptr[offset + 2] << 8) | ptr[offset + 3];
    offset += 4;
    offset &= 0x1FFF;

    if (ext_type == 0x0000) {
      if (ptr + offset + 5 > data_end)
        return 0xFFFFFFFFFFFFFFFFULL;
      __u32 sni_len = (ptr[offset + 3] << 8) | ptr[offset + 4];
      offset += 5;
      offset &= 0x1FFF;

      if (sni_len > 64)
        sni_len = 64;
      if (ptr + offset + sni_len > data_end)
        return 0xFFFFFFFFFFFFFFFFULL;

      __u64 hash = 0xcbf29ce484222325ULL;
      for (int j = 0; j < 64; j++) {
        if (j >= sni_len)
          break;
        if (ptr + offset + j + 1 > data_end)
          break;
        __u8 c = ptr[offset + j];
        if (c >= 'A' && c <= 'Z')
            c += 32;
        hash ^= c;
        hash *= 0x100000001b3ULL;
      }
      // Ensure the hash never equals our sentinel values (0=no SNI,
      // UINT64_MAX=error)
      if (hash == 0 || hash == 0xFFFFFFFFFFFFFFFFULL)
        hash = 0xFFFFFFFFFFFFFFFEULL;
      return hash;
    }

    offset += ext_len;
    offset &= 0x1FFF;
  }
  return 0xFFFFFFFFFFFFFFFFULL; // Sentinel: no SNI found after 10 extensions
}

static __always_inline int
check_tcp_socket(struct xdp_md *ctx, struct iphdr *iph, struct tcphdr *tcph) {
  struct bpf_sock_tuple tuple = {};
  tuple.ipv4.saddr = iph->saddr;
  tuple.ipv4.sport = tcph->source;

  // Default to packet's destination
  tuple.ipv4.daddr = iph->daddr;
  tuple.ipv4.dport = tcph->dest;

  // Check NAT map
  struct nat_key nkey = {};
  nkey.public_ip = iph->daddr;
  nkey.public_port = tcph->dest;
  nkey.protocol = 6; // IPPROTO_TCP

  struct nat_value *nval = bpf_map_lookup_elem(&nat_map, &nkey);
  if (!nval) {
    nkey.public_ip = 0; // Try wildcard IP
    nval = bpf_map_lookup_elem(&nat_map, &nkey);
  }

  if (nval) {
    tuple.ipv4.daddr = nval->internal_ip;
    tuple.ipv4.dport = nval->internal_port;
  }

  struct bpf_sock *sk = bpf_skc_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4),
                                           BPF_F_CURRENT_NETNS, 0);
  if (sk) {
    bpf_sk_release(sk);
    return 1; // Socket exists
  }
  return 0; // Socket not found
}

SEC("xdp")
int xdp_ddos_filter(struct xdp_md *ctx) {
  __u32 config_key = 0;
  struct config_data *conf = bpf_map_lookup_elem(&config_map, &config_key);
  __u32 current_rate_limit = 100000;
  __u32 current_udp_limit = 100000;
  __u32 sni_filtering = 0;
  __u32 strict_tcp_tracking = 0;
  if (conf) {
    current_rate_limit = conf->rate_limit_pps;
    current_udp_limit = conf->global_udp_pps;
    sni_filtering = conf->sni_filtering;
    strict_tcp_tracking = conf->strict_tcp_tracking;
  }

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end)
      return XDP_PASS;

    void *l4_hdr6 = (void *)(ip6h + 1);
    if (ip6h->nexthdr == IPPROTO_TCP) {
      struct tcphdr *tcph = (struct tcphdr *)l4_hdr6;
      if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;
      if ((tcph->urg && tcph->psh && tcph->fin) ||
          (!tcph->syn && !tcph->fin && !tcph->rst && !tcph->psh && !tcph->ack && !tcph->urg) ||
          (tcph->syn && tcph->fin) || (tcph->syn && tcph->rst)) {
        record_stat(STAT_TCP_INVALID);
        return XDP_DROP;
      }
    } else if (ip6h->nexthdr == IPPROTO_UDP) {
      struct udphdr *udph = (struct udphdr *)l4_hdr6;
      if ((void *)(udph + 1) > data_end)
        return XDP_PASS;
      if (udph->source == 0 || udph->dest == 0) {
        record_stat(STAT_UDP_INVALID);
        return XDP_DROP;
      }
    }
    return XDP_PASS;
  }

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  struct iphdr *iph = (struct iphdr *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return XDP_PASS;

  int ip_hlen = iph->ihl * 4;
  if (ip_hlen < sizeof(struct iphdr))
    return XDP_PASS;

  void *l4_hdr = (void *)iph + ip_hlen;
  if (l4_hdr > data_end)
    return XDP_PASS;

  __u32 src_ip = iph->saddr;

  // 1. Geo-Blocking (LPM Trie lookup)
  struct ipv4_lpm_key geo_key = {.prefixlen = 32, .ipv4 = src_ip};
  __u8 *blocked = bpf_map_lookup_elem(&geo_map, &geo_key);
  if (blocked && *blocked == 1) {
    record_stat(STAT_GEO_DROP);
    return XDP_DROP;
  }

  // 2. Dynamic Rate Limiting (SYN and UDP)
  if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {

    // Only inspect L4 headers if this is the first fragment
    if (!(__builtin_bswap16(iph->frag_off) & IP_OFFSET)) {
      // Protocol specific basic drops
      if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)l4_hdr;
        if ((void *)(tcph + 1) > data_end)
          return XDP_PASS;
        // Drop invalid TCP flag combinations
        if (tcph->urg && tcph->psh && tcph->fin) {
          record_stat(STAT_TCP_INVALID);
          return XDP_DROP;
        }
        // Null flags
        if (!tcph->syn && !tcph->fin && !tcph->rst && !tcph->psh &&
            !tcph->ack && !tcph->urg) {
          record_stat(STAT_TCP_INVALID);
          return XDP_DROP;
        }
        // SYN+FIN: impossible in legitimate TCP
        if (tcph->syn && tcph->fin) {
          record_stat(STAT_TCP_INVALID);
          return XDP_DROP;
        }
        // SYN+RST: impossible in legitimate TCP
        if (tcph->syn && tcph->rst) {
          record_stat(STAT_TCP_INVALID);
          return XDP_DROP;
        }

        // Layer 7 SNI Inspection for packets with payload (TLS Client Hello)
        if (sni_filtering) {
          __u16 dest_port = bpf_htons(tcph->dest);
          __u32 port_key = dest_port;
          __u8 *port_allowed =
              bpf_map_lookup_elem(&allowed_ports_map, &port_key);
          if (port_allowed && *port_allowed == 1) {
            __u32 tcp_hdr_len = tcph->doff * 4;
            if (tcp_hdr_len >= 20 && tcp_hdr_len <= 60) {
              void *payload = (void *)tcph + tcp_hdr_len;
              if (payload < data_end) { // Packet has payload
                __u64 sni_hash = parse_tls_sni(payload, data_end);
                if (sni_hash == 0xFFFFFFFFFFFFFFFFULL) {
                  record_stat(STAT_TCP_INVALID);
                  return XDP_DROP;
                } else if (sni_hash != 0) {
                  __u8 *allowed = bpf_map_lookup_elem(&sni_map, &sni_hash);
                  if (!allowed || *allowed != 1) {
                    record_stat(STAT_TCP_INVALID);
                    return XDP_DROP;
                  }
                }
              }
            }
          }
        }

        // Orphan ACK Drop — independent of SNI filtering
        if (strict_tcp_tracking && tcph->ack && !tcph->syn && !tcph->rst) {
          if (!check_tcp_socket(ctx, iph, tcph)) {
            record_stat(STAT_TCP_INVALID);
            return XDP_DROP;
          }
        }

        // Only rate limit SYN packets for TCP
        if (!tcph->syn)
          return XDP_PASS;
      }
      if (iph->protocol == IPPROTO_UDP) {
        __u64 now = bpf_ktime_get_ns();
        __u64 current_epoch = now >> 30;
        // Apply Global UDP Limit
        __u32 global_key = 0;
        struct rate_value *g_val =
            bpf_map_lookup_elem(&global_udp_rate_map, &global_key);
        if (g_val) {
          if (current_epoch > g_val->last_epoch) {
            g_val->count = 1;
            g_val->last_epoch = current_epoch;
          } else {
            __sync_fetch_and_add(&g_val->count, 1);
            if (g_val->count > current_udp_limit) {
              record_stat(STAT_GLOBAL_UDP_DROP);
              return XDP_DROP;
            }
          }
        }

        struct udphdr *udph = (struct udphdr *)l4_hdr;
        if ((void *)(udph + 1) > data_end)
          return XDP_PASS;
        if (udph->source == 0 || udph->dest == 0) {
          record_stat(STAT_UDP_INVALID);
          return XDP_DROP;
        }

        // Apply Port-Specific UDP Limit
        __u32 dest_port = bpf_htons(udph->dest);
        struct rate_value *p_val =
            bpf_map_lookup_elem(&port_udp_rate_map, &dest_port);
        if (p_val) {
          if (current_epoch > p_val->last_epoch) {
            p_val->count = 1;
            p_val->last_epoch = current_epoch;
          } else {
            __sync_fetch_and_add(&p_val->count, 1);
            __u32 port_key = dest_port;
            __u8 *port_allowed =
                bpf_map_lookup_elem(&allowed_ports_map, &port_key);
            __u32 limit =
                (port_allowed && *port_allowed == 1) ? current_udp_limit : 1000;
            if (p_val->count > limit) {
              record_stat(STAT_GLOBAL_UDP_DROP); // Reuse stat for simplicity
              return XDP_DROP;
            }
          }
        }
      }
    } // End of L4 inspection

    // Apply Rate Limit with Bloom Filter (Epoch & Dual-Budget)
    // Design note: A brand-new IP (not yet in the bloom filter) gets exactly
    // one unmetered packet per epoch. This is intentional — it absorbs
    // IP-spoofed floods that rotate source IPs by avoiding LRU map thrashing.
    // The bloom filter absorbs these IPs with O(1) space and the LRU map only
    // tracks repeat offenders.
    __u64 now = bpf_ktime_get_ns();
    __u64 current_epoch = now >> 30; // ~1.07 seconds per epoch (2^30 ns)

    __u8 is_syn_or_frag = 0;
    // NOTE: UDP non-first-fragments (frag_off > 0) intentionally bypass
    // per-port/global UDP limits (those checks require L4 header which is
    // absent) but still hit per-IP rate limiting here. This is correct — we can
    // still throttle the source IP.
    if ((__builtin_bswap16(iph->frag_off) & IP_OFFSET) ||
        iph->protocol == IPPROTO_ICMP) {
      is_syn_or_frag = 1;
    } else if (iph->protocol == IPPROTO_TCP) {
      // Re-read tcph pointer safely for the bloom filter path
      if (l4_hdr + sizeof(struct tcphdr) <= data_end) {
        struct tcphdr *tcph = (struct tcphdr *)l4_hdr;
        if (tcph->syn)
          is_syn_or_frag = 1;
      }
    }

    volatile __u32 lookup_key = src_ip;
    long bloom_err = bpf_map_peek_elem(&ip_bloom_map, (void *)&lookup_key);
    if (bloom_err == 0) {
      struct rate_value *val = bpf_map_lookup_elem(&rate_limit_map, (void *)&lookup_key);
      if (val) {
        if (current_epoch > val->last_epoch) {
          // New epoch: use __sync writes to be safe on SMP.
          // The tiny race window here is acceptable — a few packets may
          // slip through at epoch boundaries on multi-core hardware.
          __sync_fetch_and_and(&val->count, 0);
          __sync_fetch_and_add(&val->count, 1);
          __sync_fetch_and_and(&val->syn_count, 0);
          if (is_syn_or_frag)
            __sync_fetch_and_add(&val->syn_count, 1);
          val->last_epoch = current_epoch;
        } else {
          __sync_fetch_and_add(&val->count, 1);
          if (is_syn_or_frag) {
            __sync_fetch_and_add(&val->syn_count, 1);
          }
          if (val->count > current_rate_limit) {
            record_stat(STAT_RATE_LIMIT_DROP);
            return XDP_DROP;
          }
          __u32 syn_limit = current_rate_limit / 20; // 5% of primary budget
          if (syn_limit < 1000)
            syn_limit = 1000;
          if (is_syn_or_frag && val->syn_count > syn_limit) {
            record_stat(STAT_RATE_LIMIT_DROP);
            return XDP_DROP;
          }
        }
      } else {
        struct rate_value new_val = {.last_epoch = current_epoch,
                                     .count = 1,
                                     .syn_count = is_syn_or_frag ? 1 : 0};
        bpf_map_update_elem(&rate_limit_map, (void *)&lookup_key, &new_val, BPF_ANY);
      }
    } else {
      // First time seeing this IP: Push to bloom filter but DO NOT add to LRU
      // map yet. This absorbs massive random IP spoofing without thrashing the
      // LRU map.
      bpf_map_push_elem(&ip_bloom_map, (void *)&lookup_key, BPF_ANY);
    }
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
