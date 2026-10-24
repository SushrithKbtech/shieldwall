#!/usr/bin/env bash
# Kernel test: load the XDP program on a veth pair, replay a CLDAP-style flood with
# scapy from an "attacker" network namespace, and check that the live control plane
# reads the kernel counters, classifies the attack, and the kernel drops it.
#
#   sudo bash tests/xdp_kernel_test.sh
#
# Needs: clang, libbpf-dev, bpftool, python3-scapy, root.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v bpftool >/dev/null || { echo "bpftool not found"; exit 1; }
make -C bpf xdp_filter.o >/dev/null

cleanup() {
  ip link set dev sw0 xdpgeneric off 2>/dev/null || true
  ip link del sw0 2>/dev/null || true
  ip netns del swatk 2>/dev/null || true
}
trap cleanup EXIT
cleanup

ip link add sw0 type veth peer name sw1
ip netns add swatk
ip link set sw1 netns swatk
ip addr add 192.168.77.1/24 dev sw0
ip link set sw0 up
ip netns exec swatk ip addr add 192.168.77.2/24 dev sw1
ip netns exec swatk ip link set sw1 up

python3 tests/xdp_kernel_check.py
