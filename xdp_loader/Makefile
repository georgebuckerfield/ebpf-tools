KDIR = ../linux
CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))

libbpf:
	cd $(KDIR)/tools/lib/bpf && make

build: libbpf
	clang \
	-I$(KDIR)/include/uapi \
	-I$(KDIR)/include \
	-I$(KDIR)/tools/lib \
	-D__KERNEL__ \
	-L$(KDIR)/tools/lib/bpf \
	-lbpf \
	-o xdp_load.o \
	xdp_load.c
