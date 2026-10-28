# sandbox

A Linux sandbox for running untrusted programs, written in C. It combines
cgroups v2, namespaces, `pivot_root`, resource limits, dropped privileges and
a seccomp-bpf syscall allowlist, and reports a verdict (exited, TLE, MLE,
killed by seccomp, ...).

## Requirements

- Linux with cgroups v2 and root access (tested on Kali, kernel 6.18)
- `sudo apt install build-essential libseccomp-dev busybox-static`

## Build and test

    ./setup_rootfs.sh     # builds ./rootfs (busybox + test programs)
    make
    make test             # runs 21 attack/control tests

## Usage

    sudo ./sandbox <seconds> <mem_mb> <rootfs> <program> [args...]

Examples:

    sudo ./sandbox 2 64 rootfs /bin/echo hi
    sudo ./sandbox 5 64 rootfs /bin/memhog      # MLE (exact): cgroup OOM kill

The program path is resolved inside the rootfs, so use absolute paths such as
`/bin/sh`.

## Verdicts

| Output | Meaning |
|---|---|
| `exited with code N` | Program finished on its own |
| `TLE` | Wall-clock limit exceeded, killed |
| `MLE (exact)` | cgroup OOM kill (memory limit) |
| `KILLED by seccomp` | Program called a forbidden syscall |
| `killed by signal N` | Crash or other signal |

## Layers

1. cgroup v2: memory.max, pids.max, kill-on-timeout
2. Namespaces: PID, mount, network, UTS, IPC
3. pivot_root into a read-only rootfs, private /tmp
4. rlimits: CPU, file size, core dumps
5. Privilege drop: empty capability bounding set, uid/gid 65534
6. seccomp-bpf allowlist with no_new_privs

See REPORT.md for the design, evidence and known limits.

## Warning

Learning project. It shares the host kernel, so do not use it as a security
boundary for hostile code without a VM around it.
