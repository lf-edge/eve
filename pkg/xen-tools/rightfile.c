#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    struct stat st;
    int fd_inum, file_inum;

    if (fstat(0, &st) < 0) {
        return -1;
    }
    fd_inum = st.st_ino;

    if (stat(argv[1], &st) < 0) {
        return -1;
    }
    file_inum = st.st_ino;

    if (file_inum == fd_inum) {
        printf("y\n");
    }

    return 0;
}
