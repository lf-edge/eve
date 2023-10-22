#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct clone_args clone_args;

struct clone_args {
    const char *chroot;
    const char *workdir;
    char **args;
    char *command;
    uid_t uid, gid;
};

#define STACK_SIZE (8 * 1024 * 1024)
static char child_stack[STACK_SIZE];    /* Space for child's stack */

static int childFunc(void *args)
{
    clone_args *parsed_args = (clone_args *)args;

    chroot(parsed_args->chroot);
    chdir(parsed_args->workdir);

    mount("proc", "/proc", "proc", 0, NULL);

    setgid(parsed_args->gid);
    setuid(parsed_args->uid);

    execvp(parsed_args->command, parsed_args->args);
}

int main(int argc, char **argv) {
    const char *pid_file = argv[5];
    uid_t uid, gid;
    char *endptr;
    pid_t child_pid;
    struct clone_args args;
    int fd;

    setsid();
    ioctl(0, TIOCSCTTY, 1);

    uid = strtol(argv[3], &endptr, 10);
    gid = strtol(argv[4], &endptr, 10);

    args = (struct clone_args) {
        .chroot = argv[1],
        .workdir = argv[2],
        .uid = uid,
        .gid = gid,
        .command = argv[6],
        .args = argv + 6,
    };
    child_pid = clone(childFunc, child_stack + STACK_SIZE,
                      CLONE_NEWPID | SIGCHLD, &args);
    if (child_pid < 0) {
        perror("clone() failed:");
        return -1;
    }

    /*
     * Open a file and write a PID of the child process in order
     * to do attach to its namespace.
     */
    fd = open(pid_file, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR);
    if (fd < 0) {
        /* Don't consider as fatal */
        perror("open(pid_file) failed:");
    } else {
        char buf[64];
        int len;

        len = snprintf(buf, sizeof(buf), "%u\n", child_pid);
        write(fd, buf, len);
        close(fd);
    }

    waitpid(child_pid, NULL, 0);
    return 0;
}
