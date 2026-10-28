#!/bin/bash
# Builds ./rootfs: busybox plus the statically linked test programs
set -e
cd "$(dirname "$0")"
command -v busybox >/dev/null || { echo "install first: sudo apt install busybox-static"; exit 1; }
mkdir -p rootfs/{bin,proc,dev,tmp,etc}
cp "$(command -v busybox)" rootfs/bin/
for a in sh ls cat echo ps id hostname sleep ifconfig ping touch dd mount grep; do
    ln -sf busybox rootfs/bin/$a
done
[ -e rootfs/dev/null ] || sudo mknod -m 666 rootfs/dev/null c 1 3
for t in segv memhog evil forkbomb attack; do
    gcc -static -o rootfs/bin/$t tests/$t.c
done
echo "rootfs ready"
