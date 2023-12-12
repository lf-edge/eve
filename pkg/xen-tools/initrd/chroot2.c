#define _GNU_SOURCE
#include <err.h>
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
#include <pwd.h>
#include <grp.h>

struct clone_args {
    const char *chroot;
    const char *workdir;
    char **args;
    char *command;
    uid_t uid, gid;
};

#define STACK_SIZE (8 * 1024 * 1024)
static char child_stack[STACK_SIZE];    /* Space for child's stack */

static int child_func(void *args)
{
    struct clone_args *parsed_args = args;
    struct passwd *pws;

    pws = getpwuid(parsed_args->uid);
    if (pws == NULL)
        err(-1, "getpwuid(%d) failed:", parsed_args->uid);

    if (initgroups(pws->pw_name, parsed_args->gid) != 0)
        err(-1, "initgroups(%s, %d) failed:", pws->pw_name, parsed_args->gid);

    if (chroot(parsed_args->chroot) != 0)
        err(-1, "chroot(%s) failed:", parsed_args->chroot);

    if (chdir(parsed_args->workdir) != 0)
        err(-1, "chdir(%s) failed:", parsed_args->workdir);

    if (mount("proc", "/proc", "proc", 0, NULL) != 0)
        err(-1, "mount(proc) failed:");

    if (setgid(parsed_args->gid) != 0 )
        err(-1, "setgid(%d) failed:", parsed_args->gid);

    if (setuid(parsed_args->uid) != 0 )
        err(-1, "setuid(%d) failed:", parsed_args->uid);

    execvp(parsed_args->command, parsed_args->args);

    /* Reachable only in case of execvp() failure */
    err(-1, "execvp(%s) failed:", parsed_args->command);
}

int main(int argc, char **argv)
{
    const char *pid_file = argv[5];
    uid_t uid, gid;
    int wstatus;
    char *endptr;
    pid_t child_pid;
    struct clone_args args;
    int fd;

    if (setsid() < 0)
        err(-1, "setsid() failed:");

    if (ioctl(0, TIOCSCTTY, 1) < 0) {
#if 0
        err(-1, "ioctl(TIOCSCTTY) failed:");
else
        warn("ioctl(TIOCSCTTY) failed:");
#endif
    }
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
    child_pid = clone(child_func, child_stack + STACK_SIZE,
                      CLONE_NEWPID | SIGCHLD, &args);
    if (child_pid < 0)
        err(-1, "clone() failed:");

    /*
     * Open a file and write a PID of the child process in order
     * to do attach to its namespace.
     */
    fd = open(pid_file, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR);
    if (fd < 0) {
        /* Don't consider as fatal */
        warn("open(%s) failed (not fatal):", pid_file);
    } else {
        char buf[64];
        int len;

        len = snprintf(buf, sizeof(buf), "%u\n", child_pid);
        write(fd, buf, len);
        close(fd);
    }

    child_pid = wait(&wstatus);
    if (child_pid < 0)
        err(-1, "wait() failed:");

    return WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;
}
