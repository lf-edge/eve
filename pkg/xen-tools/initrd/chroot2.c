#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
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

// Create the input and output pipes to multiplex the main process
int input_pipe_fds[2];
int output_pipe_fds[2];

pid_t child_pid;
struct termios orig_termios_first_tty;
struct termios orig_termios_second_tty;
int fd1, fd2;

void reset_terminal_mode_first_tty() {
    tcsetattr(fd1, TCSANOW, &orig_termios_first_tty);
}

void reset_terminal_mode_second_tty() {
    tcsetattr(fd2, TCSANOW, &orig_termios_second_tty);
}

void set_raw_mode(int fd, struct termios *orig_termios) {
    struct termios raw;

    // Get current terminal settings
    tcgetattr(fd, orig_termios);

    // Modify the terminal settings to raw mode
    raw = *orig_termios;
    raw.c_lflag &= ~(ICANON | IEXTEN | ISIG);
    raw.c_iflag &= ~(BRKINT | INPCK | ISTRIP | IXON);
    raw.c_cflag |= (CS8);
    raw.c_oflag &= ~(OPOST);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;

    // Set the terminal to raw mode
    tcsetattr(fd, TCSANOW, &raw);
}

void handle_signal(int sig) {
    if (child_pid != 0) {
        // Print the signal number
        printf("Received signal: %d\n", sig);

        // Forward the signal to the child process group
        kill(-child_pid, sig);
    }
}

void write_to_all(int *fds, int num_fds, char *buffer, ssize_t bytes_read) {
    for (int i = 0; i < num_fds; i++) {
        write(fds[i], buffer, bytes_read);
    }
}

void forward_data_to_fds(int input_fd, int *output_fds, int num_output_fds) {
    char c;
    ssize_t bytes_read = read(input_fd, &c, 1);
    if (bytes_read > 0) {
        switch (c) {
        case '\n':
            // Translate newline to carriage return and newline
            write_to_all(output_fds, 2, "\r\n", 2);
            break;
        default:
            write_to_all(output_fds, 2, &c, 1);
            break;
        }
    }
}
void handle_input(int from_fd, int to_fd) {
    char c;
    ssize_t bytes_read = read(from_fd, &c, 1);
    if (bytes_read > 0) {
        switch (c) {
        case 3: // "Ctrl-C"
            handle_signal(SIGINT);
            break;
        case 4: // "Ctrl-D"
            handle_signal(SIGQUIT);
            break;
        case 26: // "Ctrl-Z"
            handle_signal(SIGTSTP);
            break;
        case 28: // "Ctrl-\"
            handle_signal(SIGQUIT);
            break;
        default:
            write(to_fd, &c, 1);
            break;
        }
    }
}

static int child_func(void *args)
{
    struct clone_args *parsed_args = args;
    struct passwd *pws;

    /* We are going to redirect the child stdin, stdout and stderr
     to the corresponding pipes, close other unneeded FDs and
     additionally create a new process group for the child and
     make it the leader to ensure correct signal handling in
     case it's a shell */

    // Create a new process group and make the child process the leader
    if (setpgid(0, 0) == -1) {
        perror("setpgid");
        exit(EXIT_FAILURE);
    }

    // Close the read end of the output pipe
    close(output_pipe_fds[0]);

    // Redirect stdout and stderr to the read end of output pipe
    dup2(output_pipe_fds[1], STDOUT_FILENO);
    dup2(output_pipe_fds[1], STDERR_FILENO);

    // Close the original write end of the output pipe
    close(output_pipe_fds[1]);

    // Close the write end of the input pipe
    close(input_pipe_fds[1]);

    // Redirect the read end of the input pipe to stdin
    dup2(input_pipe_fds[0], STDIN_FILENO);

    // Close the original read end of the input pipe
    close(input_pipe_fds[0]);

    /* Continuing with processing the arguments and exec the child process */

    if (chroot(parsed_args->chroot) != 0)
        err(-1, "chroot(%s) failed:", parsed_args->chroot);

    if (chdir(parsed_args->workdir) != 0)
        err(-1, "chdir(%s) failed:", parsed_args->workdir);

    pws = getpwuid(parsed_args->uid);
    if (pws == NULL)
        err(-1, "getpwuid(%d) failed:", parsed_args->uid);

    if (initgroups(pws->pw_name, parsed_args->gid) != 0)
        err(-1, "initgroups(%s, %d) failed:", pws->pw_name, parsed_args->gid);

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
    struct clone_args args;
    int fd;

    if (setsid() < 0)
        err(-1, "setsid() failed:");

    if (ioctl(0, TIOCSCTTY, 1) < 0)
        err(-1, "ioctl(TIOCSCTTY) failed:");

    uid = strtol(argv[3], &endptr, 10);
    gid = strtol(argv[4], &endptr, 10);

    // Create the input pipe
    if (pipe(input_pipe_fds) == -1) {
        perror("input_pipe");
        exit(EXIT_FAILURE);
    }

    // Create the output pipe
    if (pipe(output_pipe_fds) == -1) {
        perror("output_pipe");
        exit(EXIT_FAILURE);
    }

    args = (struct clone_args) {
        .chroot = argv[1],
        .workdir = argv[2],
        .uid = uid,
        .gid = gid,
        .command = argv[8],
        .args = argv + 8,
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


    // Open the TTYs without O_NOCTTY
    fd1 = open(argv[6], O_RDWR);
    if (fd1 == -1) {
        perror("open first tty");
        exit(EXIT_FAILURE);
    }

    fd2 = open(argv[7], O_RDWR);
    if (fd2 == -1) {
        perror("open second tty");
        close(fd1);
        exit(EXIT_FAILURE);
    }

    // Set both tty's to raw mode
    set_raw_mode(fd1, &orig_termios_first_tty);
    set_raw_mode(fd2, &orig_termios_second_tty);

    // Ensure raw mode is reset on exit
    atexit(reset_terminal_mode_first_tty);
    atexit(reset_terminal_mode_second_tty);

    // Handle signals
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGHUP, handle_signal);
    signal(SIGQUIT, handle_signal);

    int write_pid = fork();
    if (write_pid == -1) {
        perror("fork of write");
        exit(EXIT_FAILURE);
    }

    if (write_pid == 0) {  // Write process
        // Close the write end of the output pipe in the write process
        close(output_pipe_fds[1]);
        // Close all ends of the input pipe in the write process
        close(input_pipe_fds[0]);
        close(input_pipe_fds[1]);

        // Put the TTYs in an array
        int output_fds[2] = {fd1, fd2};

        while (1) {
            /* In the main loop this process reads from the pipe
             and writes to all FDs from output_fds */
            forward_data_to_fds(output_pipe_fds[0], output_fds, 2);
        }

        close(fd1);
        close(fd2);
        close(output_pipe_fds[0]);
    } else {  // Continuing with parent process (read process)
        // Close all ends of the output pipe in the read process
        close(output_pipe_fds[0]);
        close(output_pipe_fds[1]);
        // Close the read end of the input pipe in the read process
        close(input_pipe_fds[0]);

        int max_fd = (fd1 > fd2) ? fd1 : fd2;

        while (1) {
            /* In the main loop this process waits for input on any FD
             and forwards it to the main exec process */
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(fd1, &read_fds);
            FD_SET(fd2, &read_fds);

            int select_result = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
            if (select_result == -1) {
                if (errno == EINTR) {
                    // Interrupted by a signal, check if the exec process has terminated
                    int status;
                    pid_t result = waitpid(child_pid, &status, WNOHANG);
                    if (result == 0) {
                        // Exec process is still running
                        continue;
                    } else if (result == -1) {
                        perror("waitpid");
                        close(fd1);
                        close(fd2);
                        close(input_pipe_fds[1]);
                        exit(EXIT_FAILURE);
                    } else {
                        // Child has terminated, exit the parent process
                        if (WIFEXITED(status) || WIFSIGNALED(status)) {
                            close(fd1);
                            close(fd2);
                            close(input_pipe_fds[1]);
                            exit(EXIT_SUCCESS);
                        }
                    }
                } else {
                    perror("select");
                    close(fd1);
                    close(fd2);
                    close(input_pipe_fds[1]);
                    kill(child_pid, SIGKILL);
                    exit(EXIT_FAILURE);
                }
            }

            // Handle input from TTY10
            if (FD_ISSET(fd1, &read_fds)) {
                handle_input(fd1, input_pipe_fds[1]);
            }

            // Handle input from TTY20
            if (FD_ISSET(fd2, &read_fds)) {
                handle_input(fd2, input_pipe_fds[1]);
            }
        }

        close(fd1);
        close(fd2);
        close(input_pipe_fds[1]);
    }

    child_pid = wait(&wstatus);
    if (child_pid < 0)
        err(-1, "wait() failed:");

    return WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;
}
