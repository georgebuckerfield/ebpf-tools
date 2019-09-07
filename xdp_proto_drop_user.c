/*
Load the XDP program and pin the map to the filesystem so the list of blocked
protocols can be updated dynamically.
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

  char *filename = argv[1];
  char *device = argv[2];

  printf("got arg %s\n", argv[1]);
  struct bpf_prog_load_attr prog_load_attr = {
      .prog_type = BPF_PROG_TYPE_XDP,
      .file = filename,
  };
  struct bpf_object *obj;
  struct bpf_map *map;
  int map_fd;
  int ifindex;
  int prog_fd;

  // attempt to load the xdp program
  if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
    error(1, errno, "can't load %s", prog_load_attr.file);

  // load the map
  map = bpf_object__find_map_by_name(obj, xdp_map_name);
  if (!map)
    error(1, errno, "can't load map");
  // get a file descriptor for the map
  map_fd = bpf_map__fd(map);
  if (map_fd < 0)
    error(1, errno, "can't get map fd");

  if (bpf_obj_pin(map_fd, xdp_map_filename) != 0) {
    error(1, errno, "can't pin map to filesystem");
  }

  // get the interface index for the device
  ifindex = if_nametoindex(device);
  if (!ifindex)
    error(1, errno, "unknown interface %s\n", device);

  // attach the xdp program to the device
  if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0)
    error(1, errno,
          "can't attach to interface %s:%d: "
          "%d:%s\n",
          device, ifindex, errno, strerror(errno));

  return 0;
}
