#define _GNU_SOURCE
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
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

struct child_args {
    const char *rootfs;
    char **argv;          /* program + args, NULL-terminated */
    long mem_mb;
    double limit;
};

/* Runs as PID 1 inside the new namespaces */
static int child_main(void *p) {
    struct child_args *a = p;

    /* 1. Make all mounts private so nothing propagates to the host */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        FAIL("make mounts private");

    /* 2. pivot_root needs the new root to be a mount point: bind it to itself,
          then remount it read-only */
    if (mount(a->rootfs, a->rootfs, NULL, MS_BIND | MS_REC, NULL) < 0)
        FAIL("bind rootfs");
    if (mount(NULL, a->rootfs, NULL,
              MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID, NULL) < 0)
        FAIL("remount rootfs read-only");

    /* 3. Swap roots. pivot_root(".", ".") stacks the old root on top of the
          new one; detaching it then makes the host filesystem unreachable. */
    if (chdir(a->rootfs) < 0) FAIL("chdir rootfs");
    if (syscall(SYS_pivot_root, ".", ".") < 0) FAIL("pivot_root");
    if (umount2(".", MNT_DETACH) < 0) FAIL("umount old root");
    if (chdir("/") < 0) FAIL("chdir /");

    /* 4. Mount /proc (shows only our PID namespace) and a small writable /tmp */
    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0)
        FAIL("mount /proc");
    if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV,
              "size=16m,mode=1777") < 0)
        FAIL("mount /tmp");

    sethostname("sandbox", 7);

    /* 5. Don't leak the host's environment variables into the sandbox */
    clearenv();
    setenv("PATH", "/bin", 1);

    /* 6. Resource limits (Phase 2) */
    rlim_t mem = (rlim_t)a->mem_mb * 1024 * 1024;
    rlim_t cpu = (rlim_t)a->limit + 1;
    set_limit(RLIMIT_AS,    mem, mem);
    set_limit(RLIMIT_CPU,   cpu, cpu + 1);
    set_limit(RLIMIT_FSIZE, 10 << 20, 10 << 20);
    set_limit(RLIMIT_CORE,  0, 0);

    execvp(a->argv[0], a->argv);
    perror("execvp");
    _exit(127);
}

static void report(int status, struct rusage *ru, long mem_mb) {
    long peak_mb = ru->ru_maxrss / 1024;

    if (WIFEXITED(status)) {
        printf("[sandbox] exited with code %d\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (sig == SIGXCPU)
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
            kill(pid, SIGKILL);          /* PID 1 dies, so the whole namespace dies */
            wait4(pid, &status, 0, &ru);
            printf("[sandbox] TLE (limit %.1fs)\n", limit);
            return 0;
        }
        usleep(10000);
    }
}
