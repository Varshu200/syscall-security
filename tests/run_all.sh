#!/bin/bash
# usage: sudo tests/run_all.sh
cd "$(dirname "$0")/.." || exit 1
[ "$EUID" -eq 0 ] || { echo "run with sudo"; exit 2; }
R=rootfs
pass=0; fail=0

# t "name" "expected regex" <sandbox args: seconds mem_mb rootfs program...>
t() {
    local name=$1 re=$2; shift 2
    local out
    out=$(timeout 20 ./sandbox "$@" 2>&1)
    if echo "$out" | grep -Eq "$re" && ! echo "$out" | grep -q ESCAPED; then
        printf 'PASS  %-24s %s\n' "$name" "$(echo "$out" | grep -F '[sandbox]' | head -1)"
        pass=$((pass+1))
    else
        printf 'FAIL  %-24s expected /%s/\n' "$name" "$re"
        echo "$out" | sed 's/^/        /'
        fail=$((fail+1))
    fi
}

echo "== controls (must work) =="
t "normal program"       'exited with code 0'        2 64 $R /bin/echo hi
t "runs as nobody"       'uid=65534'                 2 64 $R /bin/id
t "tmp is writable"      '^hi$'                      2 64 $R /bin/sh -c 'echo hi > /tmp/f; cat /tmp/f'

echo "== isolation =="
t "no host files"        'BLOCKED: host'             2 64 $R /bin/attack readhost
t "rootfs read-only"     'BLOCKED: rootfs'           2 64 $R /bin/attack writeroot
t "cannot regain root"   'BLOCKED: setuid'           2 64 $R /bin/attack getroot

echo "== seccomp =="
t "no network"           'KILLED by seccomp'         2 64 $R /bin/evil socket
t "no ptrace"            'KILLED by seccomp'         2 64 $R /bin/evil ptrace
t "no unshare"           'KILLED by seccomp'         2 64 $R /bin/evil unshare
t "no namespace clone"   'KILLED by seccomp'         2 64 $R /bin/evil clonens
t "no chroot"            'KILLED by seccomp'         2 64 $R /bin/attack chroot
t "no mknod"             'KILLED by seccomp'         2 64 $R /bin/attack mknod
t "no sethostname"       'KILLED by seccomp'         2 64 $R /bin/hostname hacked

echo "== resource limits =="
t "wall-clock limit"     'TLE'                       2 64 $R /bin/sleep 5
t "cpu busy loop"        'TLE'                       1 64 $R /bin/sh -c 'while :; do :; done'
t "memory hog"           'MLE \(exact\)'             5 64 $R /bin/memhog
t "fork bomb"            'fork refused after'        5 64 $R /bin/forkbomb
t "file size limit"      'file size limit exceeded|File too large'  5 64 $R /bin/attack bigfile
t "crash (segfault)"     'signal 11'                 2 64 $R /bin/segv

echo "== cleanup =="
./sandbox 2 64 $R /bin/sh -c 'sleep 30 & sleep 30' >/dev/null 2>&1
sleep 0.5
if pgrep -x sleep >/dev/null; then
    echo "FAIL  orphan processes survive"; pkill -x sleep; fail=$((fail+1))
else
    echo "PASS  no orphan processes";      pass=$((pass+1))
fi
if ls /sys/fs/cgroup | grep -q '^sandbox-'; then
    echo "FAIL  leftover cgroups"; fail=$((fail+1))
else
    echo "PASS  no leftover cgroups"; pass=$((pass+1))
fi

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
