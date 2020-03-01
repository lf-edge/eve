#include <unistd.h>
#include <sys/ioctl.h>

int main(int argc, char **argv) {
    setsid();
    ioctl(0, TIOCSCTTY, 1);

    chroot(argv[1]);
    chdir(argv[2]);

    return execvp(argv[3], argv + 3);
}
