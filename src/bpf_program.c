#include <stdio.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define IP_NUM 100

// entry point
SEC("mysection")
int myprogram(struct xdp_md *ctx)
{
  int ipsize = 0;
  // poiter on the beginning of raw buffer
  void *data = (void *) (long) ctx->data;
  // pointer on the end of raw buffer
  void *data_end = (void *) (long) ctx->data_end;

  unsigned int ips[IP_NUM];
  for(size_t ind = 0; ind < IP_NUM; ++ind) {ips[ind]=0;}

  // pointer on the beginning of ethernet header
  struct ethhdr *eth = data;
  struct iphdr *ip;

  // size of ethernet header
  ipsize = sizeof(*eth);

  // pointer on the beginnig of ip header (comes ater ethernet heaer)
  ip = data + ipsize;

  // size of ip and ehthernet headers in bytes
  ipsize += sizeof(struct iphdr);

  // check if there is anything else in buffer or ip header does not
  // exceeds the buffer limits
  if (data + ipsize > data_end)
  {
    return XDP_DROP;
  }

  // Forbidden ips
  

  // check if source ip is facebook ip_4, theb drop package
  unsigned int source_adr = (unsigned int) ip->saddr;

  for(size_t ind = 0; ind < IP_NUM; ++ind)
  {
    if (source_adr == ips[ind])
    {
      return XDP_DROP;
    }
  }

  return XDP_PASS;
}