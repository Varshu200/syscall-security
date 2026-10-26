#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Child-side helper: apply one limit or abort the child */
static void set_limit(int res, rlim_t soft, rlim_t hard) {
    struct rlimit rl = { .rlim_cur = soft, .rlim_max = hard };
    if (setrlimit(res, &rl) < 0) {
        perror("setrlimit");
        _exit(1);
    }
}

static void report(int status, struct rusage *ru, long mem_mb) {
    long peak_mb = ru->ru_maxrss / 1024;       /* ru_maxrss is in KB on Linux */

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
    if (argc < 4) {
        fprintf(stderr, "usage: %s <seconds> <mem_mb> <program> [args...]\n",
                argv[0]);
        return 2;
    }

    double limit = atof(argv[1]);
    long mem_mb  = atol(argv[2]);
    if (limit <= 0 || mem_mb <= 0) {
        fprintf(stderr, "seconds and mem_mb must be > 0\n");
        return 2;
    }

    pid_t pid = fork();
    if (pid < 0) die("fork");

    if (pid == 0) {                                   /* CHILD */
        setpgid(0, 0);                                /* own process group */

        rlim_t mem = (rlim_t)mem_mb * 1024 * 1024;
        rlim_t cpu = (rlim_t)limit + 1;               /* backstop for wall timer */

        set_limit(RLIMIT_AS,    mem, mem);
        set_limit(RLIMIT_CPU,   cpu, cpu + 1);
        set_limit(RLIMIT_FSIZE, 10 << 20, 10 << 20);  /* 10 MB */
        set_limit(RLIMIT_CORE,  0, 0);

        execvp(argv[3], &argv[3]);
        perror("execvp");
        _exit(127);
    }

    /* PARENT */
    setpgid(pid, pid);                  /* also set here, avoids a startup race */
    double start = now();
    int status;
    struct rusage ru;

    for (;;) {
        pid_t r = wait4(pid, &status, WNOHANG, &ru);

        if (r == pid) {
            kill(-pid, SIGKILL);        /* clean up any leftover children */
            report(status, &ru, mem_mb);
            return 0;
        }
        if (r < 0) die("wait4");

        if (now() - start > limit) {
            kill(-pid, SIGKILL);        /* negative PID = whole process group */
            wait4(pid, &status, 0, &ru);
            printf("[sandbox] TLE (limit %.1fs)\n", limit);
            return 0;
        }
        usleep(10000);
    }
}
