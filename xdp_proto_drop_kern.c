// SPDX-License-Identifier: GPL-2.0

/*
XDP program to drop packets that match blocked IP protocols
*/

#define KBUILD_MODNAME "xdp_proto_drop"
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>

#include "bpf_helpers.h"
#include <uapi/linux/bpf.h>

#include "xdp_proto_drop_common.h"

struct bpf_map_def SEC("maps") xdp_block_protocols = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 10,
};

/* Parse IPv4 packet to get SRC, DST IP and protocol */
static inline int parse_ipv4(void *data, __u64 nh_off, void *data_end,
                             __be32 *src, __be32 *dest) {
  struct iphdr *iph = data + nh_off;
  // Make sure we're not going outside the body of the packet
  if (iph + 1 > data_end)
    return 0;

  *src = iph->saddr;
  *dest = iph->daddr;
  return iph->protocol;
}

// Variadic macro to wrap around bpf_trace_printk
#define bpf_printk(fmt, ...)                                                   \
  ({                                                                           \
    char ____fmt[] = fmt;                                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })

SEC("icmp_drop")
int xdp_icmp_drop(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;

  __be32 dest_ip, src_ip;
  __u16 h_proto;
  __u64 nh_off;
  int ipproto;

  bpf_printk("xdp_icmp_drop\n");

  nh_off = sizeof(*eth);
  if (data + nh_off > data_end)
    goto pass;

  /* parse vlan */
  h_proto = eth->h_proto;
  if (h_proto == __constant_htons(ETH_P_8021Q) ||
      h_proto == __constant_htons(ETH_P_8021AD)) {
    // Packet has VLAN header
    struct vlan_hdr *vhdr;

    vhdr = data + nh_off;
    if (vhdr + 1 > data_end)
      goto pass;
    nh_off += sizeof(struct vlan_hdr);
    h_proto = vhdr->h_vlan_encapsulated_proto;
  }
  if (h_proto != __constant_htons(ETH_P_IP))
    goto pass;

  ipproto = parse_ipv4(data, nh_off, data_end, &src_ip, &dest_ip);
  // Drop ICMP packets
  int *match;
  match = bpf_map_lookup_elem(&xdp_block_protocols, &ipproto);
  if (!match)
    return XDP_PASS;
  if (*match == 1)
    bpf_printk("rcvd IP packet with protocol %d, dropping\n", ipproto);
  return XDP_DROP;

pass:
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
