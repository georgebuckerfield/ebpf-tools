/*
Use this program to update the map of blocked protocols
./xdp_proto_drop_cmd.o <protocol_number>
*/

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <error.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <uapi/linux/bpf.h>

#include "xdp_proto_drop_common.h"

int main(int argc, char *argv[]) {
  int proto = atoi(argv[1]);

  int fd;
  fd = bpf_obj_get(xdp_map_filename);
  if (fd < 0) {
    error(1, errno, "failed to open map file %s\n", xdp_map_filename);
  }
  int res;
  int value;
  value = 1;
  res = bpf_map_update_elem(fd, &proto, &value, BPF_ANY);
  if (res != 0) {
    error(1, errno, "failed to update map\n");
  }
}
