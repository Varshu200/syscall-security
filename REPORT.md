# Sandbox: design report

## 1. Goal and threat model
TODO (your words): what are you protecting against? List 4-5 attacks.
What is out of scope (kernel bugs, side channels, hardware)?

## 2. Architecture
TODO: a diagram of the layers, outermost to innermost, and the order in which
the child sets them up. Explain why seccomp is loaded last.

## 3. Evidence: attack vs layer
| Attack | Layer that stops it | Suite result |
|---|---|---|
| Read host /etc/shadow | pivot_root | BLOCKED: host |
| Write into rootfs | read-only mount | BLOCKED: rootfs |
| Regain root | dropped capabilities + uid | BLOCKED: setuid |
| Open a socket | seccomp | KILLED by seccomp |
| ptrace, unshare, namespace clone | seccomp (+ clone arg filter) | KILLED by seccomp |
| chroot, mknod, sethostname | seccomp | KILLED by seccomp |
| Memory hog | cgroup memory.max | MLE (exact) |
| Fork bomb | cgroup pids.max | fork refused |
| Infinite loop / sleep | timer + RLIMIT_CPU | TLE |
| Huge file | RLIMIT_FSIZE | EFBIG / SIGXFSZ |
| Orphan processes | PID namespace + cgroup.kill | none survive |

## 4. Bugs and lessons
TODO: explain each in 2-3 sentences, in your own words.
- False positives and the trace/diff/add workflow
- Why prctl got an argument filter
- The cgroup race and why the sync pipe is needed
- The unused-function warning that pointed at the missing cg_setup call
- Verdicts only reflect the top-level process (sh -c example)
- PID 1 drops SIGXFSZ: EFBIG as PID 1, rc=153 as PID 2

## 5. Known limitations
TODO: ioctl and execve are broadly allowed, shared host kernel,
CapInh not cleared, no per-process seccomp verdicts, ...

## 6. Comparison
TODO: read nsjail or bubblewrap source. Note three differences from this design.
