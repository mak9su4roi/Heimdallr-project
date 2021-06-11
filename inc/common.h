#ifndef MAPS_INC_COMMON_H_
#define MAPS_INC_COMMON_H_

#include <linux/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


enum
{
  NOT_FOUND = -1,
  DROP_RULE =  1,
  PASS_RULE =  0,
  DROP_CASH =  3
};


typedef struct
{
  __u32 prefixlen;
  __u8  data[4];
} trie_key;

typedef __u32 hash_key;

typedef __u32 map_entry;

typedef struct
{
  int hash_fd;
  int trie_fd;
  char **args;
  int arg_num;
  int use_trie;
} map_data;
#endif //MAPS_INC_COMMON_H_
