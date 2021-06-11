#define KBUILD_MODNAME "xdp_dummy"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "common.h"

#define SEC(NAME) __attribute__((section(NAME), used))
#define MAX_TRIES 1000000
#define MAX_HASH  1000000
#define MAX_CASH  100


struct bpf_map_def SEC("maps") trie_map = {
      .type        = BPF_MAP_TYPE_LPM_TRIE,
      .key_size    = sizeof(trie_key),
      .value_size  = sizeof(__u32),
      .max_entries = MAX_TRIES,
      .map_flags   = BPF_F_NO_PREALLOC
};

struct bpf_map_def SEC("maps") hash_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = MAX_HASH,
    .map_flags   = 0
};

#ifdef HEIMDALLR_CASH
struct bpf_map_def SEC("maps") cash_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = MAX_CASH,
    .map_flags   = 0
};
#endif

SEC("tx")
int xdp_tx(struct xdp_md *ctx)
{
  __u32* value;
  int step = 0;
  // pointer on the beginning of raw buffer
  void *data = (void *)(long)ctx->data;
  // pointer on the end of raw buffer
  void *data_end = (void *)(long)ctx->data_end;

  // pointer on the beginning of ethernet header
  struct iphdr  *ip;

  // size of ethernet header
  step = sizeof(struct ethhdr);

  // pointer on the beginning of ip header (comes after ethernet header)
  ip = data + step;
  // size of ip and Ethernet headers in bytes
  step += sizeof(struct iphdr);

  // check if there is anything else in buffer or ip header does not
  // exceed the buffer limits
  if (data + step > data_end) goto invalid;
  trie_key key =
  {
      .prefixlen = 32,
      .data = {ip->saddr & 0xff, (ip->saddr >> 8) & 0xff, (ip->saddr >> 16) & 0xff, (ip->saddr >> 24) & 0xff}
  };

  value = bpf_map_lookup_elem(&hash_map, &(ip->saddr));
  // check if IPv4 is either forbidden as a single or forbidden as cashed entry
  if (value && ((*value)&DROP_RULE) == DROP_RULE) goto drop;
  // check if IPv4 is allowed
  if (value && *value == PASS_RULE) goto pass;

#ifdef HEIMDALLR_CASH
  value = bpf_map_lookup_elem(&cash_map, &(ip->saddr));
  // check if IPv4 is either forbidden as a single or forbidden as cashed entry
  if (value && ((*value)&DROP_RULE) == DROP_RULE) goto drop;
  // check if IPv4 is allowed
  if (value && *value == PASS_RULE) goto pass;
#endif

  value = bpf_map_lookup_elem(&trie_map, &key);
  // check if IPv4 is in forbidden range
  if (value && *value == DROP_RULE)
  {
#ifdef HEIMDALLR_CASH // Cashing IPv4
    __u32 cash = DROP_RULE;
    bpf_map_update_elem(&cash_map, &(ip->saddr), &cash, BPF_ANY);
#endif
    goto drop;
  }

pass:
#ifdef HEIMDALLR_DEBUG
  {
    __u32 ipv4 = ip->saddr;
    bpf_printk("PASSED: %x on iff: %d", ipv4, ctx->ingress_ifindex);
  }
#endif
  return XDP_PASS;

drop:
#ifdef HEIMDALLR_DEBUG
  {
    __u32 ipv4 = ip->saddr;
    bpf_printk("DROPPED: %x on iff: %d", ipv4, ctx->ingress_ifindex);
  }
#endif
  return XDP_DROP;

invalid:
  return XDP_DROP;
}




char _license[] SEC("license") = "GPL";
