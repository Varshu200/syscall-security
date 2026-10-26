#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    size_t n = 0;
    for (;;) {
        char *p = malloc(1 << 20);
        if (!p) { fprintf(stderr, "malloc failed after %zu MB\n", n); abort(); }
        memset(p, 1, 1 << 20);          /* touch it so it's really used */
        n++;
    }
}
