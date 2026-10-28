#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int blocked(const char *what) {
    printf("BLOCKED: %s (%s)\n", what, strerror(errno));
    return 0;
}
static int escaped(const char *what) {
    printf("ESCAPED: %s\n", what);
    return 1;
}

int main(int argc, char **argv) {
    const char *m = argc > 1 ? argv[1] : "";

    if (!strcmp(m, "readhost"))
        return open("/etc/shadow", O_RDONLY) >= 0
               ? escaped("read /etc/shadow") : blocked("host /etc/shadow");
    if (!strcmp(m, "writeroot"))
        return open("/bin/pwned", O_CREAT | O_WRONLY, 0755) >= 0
               ? escaped("wrote into rootfs") : blocked("rootfs is read-only");
    if (!strcmp(m, "getroot"))
        return setuid(0) == 0 ? escaped("became root") : blocked("setuid(0)");
    if (!strcmp(m, "chroot"))
        return chroot("/tmp") == 0 ? escaped("chroot") : blocked("chroot");
    if (!strcmp(m, "mknod"))
        return mknod("/tmp/null", S_IFCHR | 0666, makedev(1, 3)) == 0
               ? escaped("created device node") : blocked("mknod");
    if (!strcmp(m, "bigfile")) {
        static char buf[1 << 20];
        int fd = open("/tmp/big", O_CREAT | O_WRONLY, 0644);
        for (int i = 0; i < 100; i++)
            if (write(fd, buf, sizeof buf) < 0) return blocked("write failed");
        return escaped("wrote 100 MB");
    }
    fprintf(stderr, "unknown mode '%s'\n", m);
    return 2;
}
