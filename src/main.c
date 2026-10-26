#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <program> [args...]\n", argv[0]);
        return 2;
    }

    pid_t pid = fork();
    if (pid < 0) die("fork");

    if (pid == 0) {                       /* CHILD */
        execvp(argv[1], &argv[1]);
        perror("execvp");                 /* only reached on failure */
        _exit(127);
    }

    /* PARENT */
    int status;
    if (waitpid(pid, &status, 0) < 0) die("waitpid");

    if (WIFEXITED(status))
        printf("[sandbox] exited with code %d\n", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        printf("[sandbox] killed by signal %d (%s)\n",
               WTERMSIG(status), strsignal(WTERMSIG(status)));
    return 0;
}
