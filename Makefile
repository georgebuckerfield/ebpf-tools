KDIR = ./linux
CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))

install-dependencies:
	sudo apt update && \
	sudo apt install -y \
	libssl-dev \
  libelf-dev \
  flex \
  bison \
  pkg-config

config-kernel:
	cd $(KDIR) && make oldconfig
