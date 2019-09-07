/*
Utility to load XDP programs to a network device.
*/

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <error.h>
#include <net/if.h>
#include <string.h>

static void list_avail_progs(struct bpf_object *obj) {
  struct bpf_program *pos;

  printf("BPF object (%s) listing avail --progsec names\n",
         bpf_object__name(obj));

  bpf_object__for_each_program(pos, obj) {
    if (bpf_program__is_xdp(pos))
      printf(" %s\n", bpf_program__title(pos, false));
  }
}

int main(int argc, char *argv[]) {

  char *filename = argv[1];
  char *device = argv[2];

  printf("got arg %s\n", argv[1]);
  struct bpf_prog_load_attr prog_load_attr = {
      .prog_type = BPF_PROG_TYPE_XDP,
      .file = filename,
  };
  struct bpf_object *obj;

  int ifindex;
  int prog_fd;

  // attempt to load the xdp program
  if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
    error(1, errno, "can't load %s", prog_load_attr.file);

  list_avail_progs(obj);

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

  // detach the xdp program
  // bpf_set_link_xdp_fd(ifindex, -1, 0);
  return 0;
}
