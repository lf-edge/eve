#include <unistd.h>
#include <sys/ioctl.h>

int main(int argc, char **argv) {
    uid_t uid, gid;
    char *endptr;

    setsid();
    ioctl(0, TIOCSCTTY, 1);

    chroot(argv[1]);
    chdir(argv[2]);

    uid = strtol(argv[3], &endptr, 10);
    gid = strtol(argv[4], &endptr, 10);

    setgid(gid);
    setuid(uid);

    return execvp(argv[5], argv + 5);
}
