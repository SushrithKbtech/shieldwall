# Build the XDP data plane. Needs clang, llvm and libbpf headers:
#   sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r)
CLANG ?= clang
ARCH  := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

xdp_filter.o: xdp_filter.c
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/$(shell uname -m)-linux-gnu -c $< -o $@

attach: xdp_filter.o
	sudo ip link set dev $(IFACE) xdpgeneric obj xdp_filter.o sec xdp

detach:
	sudo ip link set dev $(IFACE) xdpgeneric off

clean:
	rm -f xdp_filter.o

.PHONY: attach detach clean
