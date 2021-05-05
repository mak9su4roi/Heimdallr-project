#ifndef MAPS_INC_MAP_DRIVER_HPP_
#define MAPS_INC_MAP_DRIVER_HPP_

#include <bpf.h>
#include <libbpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include "common.h"

#define DEBUG

enum
{
  IP_SIZE = 32
};

typedef struct
{
  int hash;
  int trie;
} map_fd;

typedef struct
{
  const char* hash;
  const char* trie;
} map_loc;

typedef struct
{
  void    (* add_rule)   (void* driver, char* ip, char* mask, char* type);
  void    (* drop_rule)  (void* driver, char* ip, char* mask);
  void    (* show_cash)  (void* driver);
  void    (* clear_cash) (void* driver);
  void    (* detach)     (void* driver);
  int     device;
  map_fd  fd;
  map_loc loc;
} map_driver;

void map_driver_init(map_driver* driver,
                     const char* hash_dir,
                     const char* trie_dir,
                     const char* interface);

#endif //MAPS_INC_MAP_DRIVER_HPP_
