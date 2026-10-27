#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <sched.h>
#include <seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FAIL(msg) do { perror(msg); _exit(1); } while (0)

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void set_limit(int res, rlim_t soft, rlim_t hard) {
    struct rlimit rl = { .rlim_cur = soft, .rlim_max = hard };
    if (setrlimit(res, &rl) < 0) FAIL("setrlimit");
}

/* ---------- seccomp ---------- */

#define CLONE_NS_MASK (CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | \
                       CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | \
                       CLONE_NEWNET | 0x00000080ULL /* CLONE_NEWTIME */)

static const char *allowed[] = {
    /* process lifecycle */
    "execve", "exit", "exit_group", "wait4", "waitid", "fork", "vfork",
    "kill", "tgkill", "setpgid", "getpgid", "getpgrp", "setsid",
    /* memory */
    "brk", "mmap", "munmap", "mprotect", "mremap", "madvise",
    /* file I/O */
    "read", "write", "readv", "writev", "pread64", "pwrite64",
    "open", "openat", "close", "lseek", "stat", "fstat", "lstat",
    "newfstatat", "statx", "access", "faccessat", "faccessat2",
    "readlink", "readlinkat", "getdents", "getdents64", "getcwd", "chdir",
    "dup", "dup2", "dup3", "pipe", "pipe2", "fcntl", "ioctl",
    "unlink", "unlinkat", "mkdir", "rename", "umask", "ftruncate",
    /* signals, time, identity, runtime startup */
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack",
    "clock_gettime", "clock_nanosleep", "nanosleep", "gettimeofday",
    "getpid", "getppid", "gettid", "getuid", "geteuid", "getgid", "getegid",
    "getgroups", "uname", "sysinfo", "arch_prctl", "set_tid_address",
    "set_robust_list", "rseq", "prlimit64", "getrlimit", "getrandom",
    "futex", "sched_yield", "poll", "select", "pselect6",
    "setuid", "setgid",
};

static int install_seccomp(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);   /* default deny */
    if (!ctx) return -1;

    for (size_t i = 0; i < sizeof allowed / sizeof allowed[0]; i++) {
        int nr = seccomp_syscall_resolve_name(allowed[i]);
        if (nr == __NR_SCMP_ERROR) {              /* name unknown on this arch */
            fprintf(stderr, "[sandbox] note: skipping '%s'\n", allowed[i]);
            continue;
        }
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0) < 0) goto fail;
    }

    /* clone: allowed only if NO namespace flag is set (arg0 = flags) */
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1,
                         SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NS_MASK, 0)) < 0)
        goto fail;

    /* prctl: only PR_GET_NAME and PR_SET_NAME */
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 1,
                         SCMP_A0(SCMP_CMP_EQ, PR_GET_NAME)) < 0) goto fail;
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 1,
                         SCMP_A0(SCMP_CMP_EQ, PR_SET_NAME)) < 0) goto fail;

    /* clone3: fail politely so glibc falls back to clone */
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0) < 0)
        goto fail;

    if (seccomp_load(ctx) < 0) goto fail;
    seccomp_release(ctx);
    return 0;
fail:
    seccomp_release(ctx);
    return -1;
}

/* ---------- child (PID 1 inside the new namespaces) ---------- */

/* Become an unprivileged user with no capabilities */
static void drop_privileges(void) {
    const unsigned id = 65534;                 /* "nobody" */

    /* 1. Empty the bounding set: exec can never regain a capability.
          EINVAL only means we passed the last valid capability number. */
    for (int cap = 0; cap < 64; cap++) {
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0 && errno != EINVAL)
            FAIL("PR_CAPBSET_DROP");
    }

    /* 2. Groups first, then gid, then uid */
    if (setgroups(0, NULL) < 0)     FAIL("setgroups");
    if (setresgid(id, id, id) < 0)  FAIL("setresgid");
    if (setresuid(id, id, id) < 0)  FAIL("setresuid");

    /* 3. Self-check: getting root back must fail */
    if (setuid(0) == 0) { fprintf(stderr, "still root!\n"); _exit(1); }
}

struct child_args {
    const char *rootfs;
    char **argv;
    long mem_mb;
    double limit;
};

static int child_main(void *p) {
    struct child_args *a = p;

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        FAIL("make mounts private");

    if (mount(a->rootfs, a->rootfs, NULL, MS_BIND | MS_REC, NULL) < 0)
        FAIL("bind rootfs");
    if (mount(NULL, a->rootfs, NULL,
              MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID, NULL) < 0)
        FAIL("remount rootfs read-only");

    if (chdir(a->rootfs) < 0) FAIL("chdir rootfs");
    if (syscall(SYS_pivot_root, ".", ".") < 0) FAIL("pivot_root");
    if (umount2(".", MNT_DETACH) < 0) FAIL("umount old root");
    if (chdir("/") < 0) FAIL("chdir /");

    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0)
        FAIL("mount /proc");
    if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV,
              "size=16m,mode=1777") < 0)
        FAIL("mount /tmp");

    sethostname("sandbox", 7);

    clearenv();
    setenv("PATH", "/bin", 1);

    rlim_t mem = (rlim_t)a->mem_mb * 1024 * 1024;
    rlim_t cpu = (rlim_t)a->limit + 1;
    set_limit(RLIMIT_AS,    mem, mem);
    set_limit(RLIMIT_CPU,   cpu, cpu + 1);
    set_limit(RLIMIT_FSIZE, 10 << 20, 10 << 20);
    set_limit(RLIMIT_CORE,  0, 0);

    drop_privileges();

    /* Everything privileged is done: lock the door, then start the program */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) FAIL("no_new_privs");
    if (install_seccomp() < 0) FAIL("seccomp");

    execvp(a->argv[0], a->argv);
    perror("execvp");
    _exit(127);
}

/* ---------- parent ---------- */

static void report(int status, struct rusage *ru, long mem_mb) {
    long peak_mb = ru->ru_maxrss / 1024;

    if (WIFEXITED(status)) {
        printf("[sandbox] exited with code %d\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (sig == SIGSYS)
            printf("[sandbox] KILLED by seccomp: forbidden syscall\n");
        else if (sig == SIGXCPU)
            printf("[sandbox] CPU time limit exceeded\n");
        else if (sig == SIGXFSZ)
            printf("[sandbox] file size limit exceeded\n");
        else if ((sig == SIGSEGV || sig == SIGABRT) && peak_mb > mem_mb / 2)
            printf("[sandbox] MLE (likely): signal %d (%s), peak %ld MB\n",
                   sig, strsignal(sig), peak_mb);
        else
            printf("[sandbox] killed by signal %d (%s)\n", sig, strsignal(sig));
    }
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr,
                "usage: sudo %s <seconds> <mem_mb> <rootfs> <program> [args...]\n",
                argv[0]);
        return 2;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "run with sudo (namespaces + mounts need root)\n");
        return 2;
    }

    double limit = atof(argv[1]);
    long mem_mb  = atol(argv[2]);
    if (limit <= 0 || mem_mb <= 0) {
        fprintf(stderr, "seconds and mem_mb must be > 0\n");
        return 2;
    }

    char rootfs[PATH_MAX];
    if (!realpath(argv[3], rootfs)) die("realpath rootfs");

    struct child_args args = { rootfs, &argv[4], mem_mb, limit };

    size_t stack_size = 1 << 20;
    char *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) die("mmap stack");

    int flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET |
                CLONE_NEWUTS | CLONE_NEWIPC | SIGCHLD;
    pid_t pid = clone(child_main, stack + stack_size, flags, &args);
    if (pid < 0) die("clone");

    double start = now();
    int status;
    struct rusage ru;

    for (;;) {
        pid_t r = wait4(pid, &status, WNOHANG, &ru);
        if (r == pid) {
            report(status, &ru, mem_mb);
            return 0;
        }
        if (r < 0) die("wait4");

        if (now() - start > limit) {
            kill(pid, SIGKILL);
            wait4(pid, &status, 0, &ru);
            printf("[sandbox] TLE (limit %.1fs)\n", limit);
            return 0;
        }
        usleep(10000);
    }
}
