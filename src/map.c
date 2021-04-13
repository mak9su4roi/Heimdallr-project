#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libbpf.h>
#include <bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <assert.h>

#define IP_SIZE 32

const char     *ktrie_path = "/sys/fs/bpf/trie_map";
const char     *khash_path = "/sys/fs/bpf/hash_map";
const int      karg_num = 3;
typedef struct bpf_lpm_trie_key trie_key;


void append_ipv4(void *key,
                 int   fd)
{
  __u64 value = 0;
  assert(!bpf_map_update_elem(fd, key, &value, 0));
  printf("Address appended\n");
}

int lookup_ipv4(void *key,
                int   fd)
{
  __u64 value = 0;
  assert(!bpf_map_lookup_elem(fd, key, &value) || errno == ENOENT);
  printf("%s\n", (errno == ENOENT)? "No match": "Address matched");
  return 1;
}

void drop_ipv4(void *key,
               int   fd)
{
  int rm = bpf_map_delete_elem(fd, key);
  assert(!rm || (rm == -1 && errno == ENOENT));
  printf("%s\n", (!rm)? "Address removed": "Address does not exist");
}

int main(int  argc,
         char **argv)
{
  int mask, hash_map_fd, trie_map_fd, map_fd, result;
  void *ipv4_key;
  trie_key *ipv4_trie_key;
  __u32     ipv4_hash_key;

  __u32 ipv4_key_size = sizeof(*ipv4_key) + sizeof(__u32);
  ipv4_trie_key       = alloca(ipv4_key_size);

  if (argc - 1 < karg_num)
  {
    fprintf(stderr, "No IPv4 address provided\n");
    goto fail;
  }

  if ((trie_map_fd = bpf_obj_get(ktrie_path)) < 0)
  {
    fprintf(stderr, "Failed to retrieve fd form: %s (%s)\n", ktrie_path, strerror(errno));
    goto fail;
  }

  if ((hash_map_fd = bpf_obj_get(khash_path)) < 0)
  {
    fprintf(stderr, "Failed to retrieve fd form: %s (%s)\n", khash_path, strerror(errno));
    goto fail;
  }

  printf("Trie map fd is: %d\n", trie_map_fd);
  printf("Hash map fd is: %d\n", hash_map_fd);

  sscanf(argv[2], "%u", &(ipv4_trie_key->prefixlen));
  inet_pton(AF_INET, argv[1], ipv4_trie_key->data);
  memcpy(&ipv4_hash_key, ipv4_trie_key->data, sizeof(__u32));

  ipv4_key = (void*)((ipv4_trie_key->prefixlen == IP_SIZE)? &ipv4_hash_key: ipv4_trie_key);
  map_fd   =         (ipv4_trie_key->prefixlen == IP_SIZE)? hash_map_fd: trie_map_fd;


  switch (argv[3][0])
  {
    case 'A':
    case 'a': append_ipv4(ipv4_key, map_fd);
      break;

    case 'D':
    case 'd': drop_ipv4(ipv4_key, map_fd);

      break;
    case 'L':
    case 'l': lookup_ipv4(ipv4_key, map_fd);

      break;
    default:
      printf("Unknown option: %c\n", argv[3][0]);
  }

success:
  return 0;
fail:
  return -1;
}