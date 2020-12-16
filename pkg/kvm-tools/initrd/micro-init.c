/* Author: Sergey Temerkhanov <s.temerkhanov@gmail.com>
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <stdio.h>

#define IO_FNAME "/dev/console"
#define INIT_FNAME "/init-initrd"

int main(int argc, char *argv[])
{
	int fd_in, fd_out, fd_err, ret;
	char message[255];

	fd_err = open(IO_FNAME, O_SYNC | O_WRONLY | O_CLOEXEC);
	if (fd_err < 0) {
		return 1;
	}

	ret = snprintf(message, sizeof(message), "Starting init\n");
	write(fd_err, message, ret);

	fd_in = open(IO_FNAME, O_SYNC | O_RDONLY | O_CLOEXEC);
	if (fd_err < 0) {
		ret = snprintf(message, sizeof(message), "Error opening stdin: %s\n", strerror(errno));
		if (ret > 0)
			write(fd_err, message, ret);
		return 1;
	}

	fd_out = open(IO_FNAME, O_WRONLY | O_CLOEXEC);
	if (fd_out < 0) {
		ret = snprintf(message, sizeof(message), "Error redirecting stdout %s\n", strerror(errno));
		if (ret > 0)
			write(fd_err, message, ret);
		return 1;
	}

	ret = dup2(fd_err, STDERR_FILENO);
	if (ret < 0) {
		ret = snprintf(message, sizeof(message), "Error redirecting stderr %s\n", strerror(errno));
		if (ret > 0)
			write(fd_err, message, ret);
		return 1;
	}

	ret = dup2(fd_in, STDIN_FILENO);
	if (ret < 0) {
		ret = snprintf(message, sizeof(message), "Error redirecting stdin %s\n", strerror(errno));
		if (ret > 0)
			write(fd_err, message, ret);
		return 1;
	}

	ret = dup2(fd_out, STDOUT_FILENO);
	if (ret < 0) {
		ret = snprintf(message, sizeof(message), "Error redirecting stdout %s\n", strerror(errno));
		if (ret > 0)
			write(fd_err, message, ret);
		return 1;
	}

	printf("Running payload\n");

	char *real_init = INIT_FNAME;
	char *real_init_argv[] = {real_init, NULL};
	char *real_init_envp[] = {NULL};

	ret = execve(real_init, real_init_argv, real_init_envp);

	if (ret < 0) {
		ret = snprintf(message, sizeof(message), "Error executing %s: %s\n", real_init, strerror(errno));
		if (ret > 0)
			write(fd_err, message, ret);
		return 1;
	}

	return 0;
}
