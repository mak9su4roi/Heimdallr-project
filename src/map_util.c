#include "common.h"
#include <stdio.h>
#include "map_driver.h"

#define DEBUG

const char *ktrie_path   = "/sys/fs/bpf/trie_map";
const char *khash_path   = "/sys/fs/bpf/hash_map";


enum
{
  TYPE_INDEX  = 0,
  IP_INDEX    = 1,
  MASK_INDEX  = 2,
  VALUE_INDEX = 3,
  TRIE_TYPE   = 't',
  SUCCESS     = 0,
  FAILURE     = -1
};


map_data data;


int main(int  argc,
         char **argv)
{
  if (argc < 2+1)
  {
#ifdef HEIMDALLR_DEBUG
    printf("Not enough args: %d\n", argc);
#endif
    return 0;
  }

  map_driver driver;

  char trie_path[100];
  sprintf(trie_path, "%s_%s",ktrie_path, argv[1]);

  char hash_path[100];
  sprintf(hash_path, "%s_%s",khash_path, argv[1]);

  map_driver_init(&driver, hash_path, trie_path, argv[1]);
  switch (argv[2][0])
  {
    case 'A':
    case 'a':
      for (size_t ind=0; ind*3 + 3 < argc; ++ind)
      {
        driver.add_rule(&driver, argv[3+ind*3], argv[4+ind*3], argv[5+ind*3]);
      }
      break;

    case 'D':
    case 'd':
      for (size_t ind=0; ind*2 + 3 < argc; ++ind)
      {
        driver.drop_rule(&driver, argv[3+ind*2], argv[4+ind*2]);
      }
      break;

    case 'S':
    case 's': driver.show_cash(&driver);
      break;

#ifdef HEIMDALLR_CASH
    case 'C':
    case 'c': driver.clear_cash(&driver);
      break;
#endif

    case 'E':
    case 'e': driver.detach(&driver);
  }
}