KDIR = ../linux
KERNEL ?= /lib/modules/$(shell uname -r)/build
CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))

CLANG_FLAGS = -I. -I$(KERNEL)/arch/$(ARCH)/include \
-I$(KERNEL)/arch/$(ARCH)/include/generated \
-I$(KERNEL)/include \
-I$(KERNEL)/arch/$(ARCH)/include/uapi \
-I$(KERNEL)/arch/$(ARCH)/include/generated/uapi \
-I$(KERNEL)/include/uapi \
-I$(KERNEL)/include/generated/uapi \
-include $(KERNEL)/include/linux/kconfig.h \
-I$(KERNEL)/tools/testing/selftests/bpf/ \
-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
-D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
-Wno-gnu-variable-sized-type-not-at-end \
-Wno-address-of-packed-member -Wno-tautological-compare \
-Wno-unknown-warning-option \
-O2 -emit-llvm

proto-drop: proto-drop-kernel proto-drop-user proto-drop-cmd

proto-drop-user:
	clang \
	-I$(KDIR)/include/uapi \
	-I$(KDIR)/include \
	-I$(KDIR)/tools/lib \
	-D__KERNEL__ \
	-L$(KDIR)/tools/lib/bpf \
	-lbpf \
	-o xdp_proto_drop_user.o \
	xdp_proto_drop_user.c

proto-drop-cmd:
	clang \
	-I$(KDIR)/include/uapi \
	-I$(KDIR)/include \
	-I$(KDIR)/tools/lib \
	-D__KERNEL__ \
	-L$(KDIR)/tools/lib/bpf \
	-lbpf \
	-o xdp_proto_drop_cmd.o \
	xdp_proto_drop_cmd.c

proto-drop-kernel: clean_xdp_proto_drop_kern.o xdp_proto_drop_kern.o

clean_xdp_proto_drop_kern.o:
	rm -f xdp_proto_drop_kern.o

xdp_proto_drop_kern.o: xdp_proto_drop_kern.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o - | \
	$(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $@
