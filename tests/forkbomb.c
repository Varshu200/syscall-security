#include <stdio.h>
#include <unistd.h>

int main(void) {
    int n = 0;
    for (;;) {
        pid_t p = fork();
        if (p == 0) { sleep(100); _exit(0); }   /* child just sits there */
        if (p < 0) { printf("fork refused after %d children\n", n); return 0; }
        n++;
    }
}
