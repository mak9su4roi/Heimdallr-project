#include "map_driver.h"


static void set_conf(__u8*  ip,
                     __u32* mask,
                     __u32* type,
                     char*  ip_str,
                     char*  mask_str,
                     char*  type_str)
{
  if (ip_str)   inet_pton(AF_INET, ip_str, ip);
  if (mask_str) sscanf(mask_str, "%u", mask);
  if (type_str) sscanf(type_str, "%u", type);
}


static void add_rule (void* driver,
                      char* ip_str,
                      char* mask_str,
                      char* type_str)
{
  __u32 ip, mask, type;
  __u8* octet = (__u8*)&ip;
  set_conf(octet, &mask, &type, ip_str, mask_str, type_str);
  trie_key key = {.data={octet[0], octet[1], octet[2], octet[3]}, .prefixlen=mask};
  map_driver* drv = driver;

  if (mask == IP_SIZE)
    assert(!bpf_map_update_elem(drv->fd.hash, &ip, &type, 0));
  else
    assert(!bpf_map_update_elem(drv->fd.trie, &key, &type, 0));
}


static void drop_rule (void* driver,
                       char* ip_str,
                       char* mask_str)
{
  __u32 ip, mask, rm;
  __u8* octet = (__u8*)&ip;
  set_conf(octet, &mask, NULL, ip_str, mask_str, NULL);
  trie_key key = {.data={octet[0], octet[1], octet[2], octet[3]}, .prefixlen=mask};
  map_driver* drv = driver;

  if (mask == IP_SIZE)
    rm = bpf_map_delete_elem(drv->fd.hash, &ip);
  else
    rm = bpf_map_delete_elem(drv->fd.trie, &key);
  assert(!rm || (rm == -1 && errno == ENOENT));
}


static __u32 lookup_ipv4(void *key,
                         int   fd)
{
  __u32 value = NOT_FOUND;
  assert(!bpf_map_lookup_elem(fd, key, &value) || errno == ENOENT);
  return value;
}


static void show_cash(void* driver)
{
  map_driver* drv = driver;
  int fd = drv -> fd.hash;

  __u32 next_key, lookup_key, value;
  __u8* octet = (__u8*)&next_key;
  lookup_key = -1;

  while(bpf_map_get_next_key(fd , &lookup_key, &next_key) == 0)
  {
    lookup_key = next_key;
    value = lookup_ipv4(&next_key, fd);
    if (DROP_CASH != value) continue;
    printf("%d.%d.%d.%d\n", octet[0], octet[1], octet[2], octet[3]);
  }
}


static void detach(void* driver)
{
  map_driver* drv = driver;
  bpf_set_link_xdp_fd(drv->device, -1, 0);
  remove(drv->loc.hash);
  remove(drv->loc.trie);
}


static void clear_cash(void* driver)
{
  map_driver* drv = driver;
  int hash = drv -> fd.hash;
  int trie = drv -> fd.trie;
  __u32 next_key, lookup_key, value;
  __u8* octet = (__u8*)&next_key;
  lookup_key = -1;
  trie_key key;
  key.prefixlen = 32;

  while(bpf_map_get_next_key(hash , &lookup_key, &next_key) == 0)
  {
    lookup_key = next_key;
    if (DROP_CASH != lookup_ipv4(&next_key, hash)) continue;
    memcpy(key.data, &next_key, sizeof(__u32));
    value = lookup_ipv4(&key, trie);
    if (value != NOT_FOUND && value != PASS_RULE) continue;
    char ip_str[100];
    sprintf(ip_str, "%d.%d.%d.%d", octet[0], octet[1], octet[2], octet[3]);
    drv->drop_rule(driver, ip_str, "32");
  }
}


void map_driver_init(map_driver* driver,
                     const char* hash_dir,
                     const char* trie_dir,
                     const char* interface)
{
  assert(driver);
  assert((driver->fd.trie = bpf_obj_get(trie_dir)) >= 0);
  assert((driver->fd.hash = bpf_obj_get(hash_dir)) >= 0);

  sscanf(interface, "%d", &driver->device);
  driver->loc.hash = hash_dir;
  driver->loc.trie = trie_dir;

  driver->add_rule   = &add_rule;
  driver->show_cash  = &show_cash;
  driver->drop_rule  = &drop_rule;
  driver->detach     = &detach;
  driver->clear_cash = &clear_cash;
}