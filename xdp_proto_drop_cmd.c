/*
Use this program to update the map of blocked protocols
./xdp_proto_drop_cmd.o add <protocol_number>
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

  char *action = argv[1];
  int proto = atoi(argv[2]);

  int fd;
  fd = bpf_obj_get(xdp_map_filename);
  if (fd < 0) {
    error(1, errno, "failed to open map file %s\n", xdp_map_filename);
  }
  int res;
  int value;
  if (strncmp(action, "add", sizeof(*action)) == 0) {
    value = 1;
  }
  if (strncmp(action, "del", sizeof(*action)) == 0) {
    value = 0;
  }

  res = bpf_map_update_elem(fd, &proto, &value, BPF_ANY);
  if (res != 0) {
    error(1, errno, "failed to update map\n");
  }
}
