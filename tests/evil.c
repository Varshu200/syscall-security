#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *m = argc > 1 ? argv[1] : "none";
    printf("trying: %s\n", m);
    fflush(stdout);
    if      (!strcmp(m, "socket"))  socket(AF_INET, SOCK_STREAM, 0);
    else if (!strcmp(m, "ptrace"))  ptrace(PTRACE_TRACEME, 0, 0, 0);
    else if (!strcmp(m, "unshare")) unshare(CLONE_NEWNS);
    else if (!strcmp(m, "clonens")) syscall(SYS_clone, CLONE_NEWUTS | SIGCHLD, 0, 0, 0, 0);
    printf("survived\n");
    return 0;
}
