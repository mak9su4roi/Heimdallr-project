#include <libbpf.h>
#include <bpf.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>

#define CHECK_FAIL(condition) ({					                \
	int __ret = !!(condition);					                    \
	int __save_errno = errno;					                      \
	if (__ret) {							                              \
		fprintf(stdout, "%s:FAIL:%d\n", __func__, __LINE__);	\
	}								                                        \
	errno = __save_errno;						                        \
	__ret;								                                  \
})


int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
	/* Next assignment this will move into ../common/ */
	int err;

	/* libbpf provide the XDP net_device link-level hook attach helper */
	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
		/* Force mode didn't work, probably because a program of the
		 * opposite type is loaded. Let's unload that and try loading
		 * again.
		 */

		__u32 old_flags = xdp_flags;

		xdp_flags &= ~XDP_FLAGS_MODES;
		xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
		err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		if (!err)
			err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
	}

	if (err < 0) {
		fprintf(stderr, "ERR: "
			"ifindex(%d) link set xdp fd failed (%d): %s\n",
			ifindex, -err, strerror(-err));

		switch (-err) {
		case EBUSY:
		case EEXIST:
			fprintf(stderr, "Hint: XDP already loaded on device"
				" use --force to swap/replace\n");
			break;
		case EOPNOTSUPP:
			fprintf(stderr, "Hint: Native-XDP not supported"
				" use --skb-mode or --auto-mode\n");
			break;
		default:
			break;
		}
		return -1;
	}

	return 0;
}

int main(int argc, char **argv) {
	const char *file = "bpf_program.o";
	struct bpf_object *obj;
	int err, prog_fd, trie_map_fd, hash_map_fd;

	err = bpf_prog_load(file, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (CHECK_FAIL(err))
		return -1;

	trie_map_fd = bpf_object__find_map_fd_by_name(obj, "trie_map");
  printf("Trie map fd is: %d\n", trie_map_fd);

  hash_map_fd = bpf_object__find_map_fd_by_name(obj, "hash_map");
  printf("Trie map fd is: %d\n", hash_map_fd);

	bpf_obj_pin(trie_map_fd, "/sys/fs/bpf/trie_map");
  bpf_obj_pin(hash_map_fd, "/sys/fs/bpf/hash_map");
	if (CHECK_FAIL(err))
		return -1;

	err = xdp_link_attach(2 /* ifindex of my interface (see the first number in the output of "ip addr/ip li") */,
			      XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE /* my driver doesn't support XDP_FLAGS_DRV_MODE */, prog_fd);

	printf("The kernel loaded the BPF program\n");
	return 0;
}
