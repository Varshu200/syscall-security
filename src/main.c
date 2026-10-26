#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

/* Monotonic clock in seconds: unaffected by system time changes */
static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void report(int status) {
    if (WIFEXITED(status))
        printf("[sandbox] exited with code %d\n", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        printf("[sandbox] killed by signal %d (%s)\n",
               WTERMSIG(status), strsignal(WTERMSIG(status)));
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <seconds> <program> [args...]\n", argv[0]);
        return 2;
    }

    double limit = atof(argv[1]);
    if (limit <= 0) {
        fprintf(stderr, "seconds must be > 0\n");
        return 2;
    }

    pid_t pid = fork();
    if (pid < 0) die("fork");

    if (pid == 0) {                         /* CHILD */
        execvp(argv[2], &argv[2]);
        perror("execvp");
        _exit(127);
    }

    /* PARENT: poll instead of blocking, so we can enforce the limit */
    double start = now();
    int status;

    for (;;) {
        pid_t r = waitpid(pid, &status, WNOHANG);

        if (r == pid) {                     /* child finished on its own */
            report(status);
            return 0;
        }
        if (r < 0) die("waitpid");

        /* r == 0: child still running */
        if (now() - start > limit) {
            kill(pid, SIGKILL);             /* cannot be caught or ignored */
            waitpid(pid, &status, 0);       /* reap, or it becomes a zombie */
            printf("[sandbox] TLE (limit %.1fs)\n", limit);
            return 0;
        }
        usleep(10000);                      /* sleep 10 ms, avoid busy-waiting */
    }
}
