#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_SIZE 256
#define OUTPUT_FILE "psi_stats.txt"
#define DEVICE_OUTPUT_DIR "/persist/memory-monitor/output"
#define PROC_FILE "/proc/pressure/memory"

void write_to_file(int fd, const char *buffer) {
    if (write(fd, buffer, strlen(buffer)) == -1) {
        perror("write");
        exit(EXIT_FAILURE);
    }
    if (fsync(fd) == -1) {
        perror("fsync");
        exit(EXIT_FAILURE);
    }
}

static void daemonize(void)
{
    int pid, sid;
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    // If we got a good PID, then we can exit the parent process
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // Change the file mode mask
    umask(0);

    // Create a new SID for the child process
    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }
}

int main()
{
    int fd;
    FILE *proc_file;
    char buffer[BUFFER_SIZE];
    time_t rawtime;
    struct tm *timeinfo;

    daemonize();


    // If /persist directory exists, create the output file there, otherwise create it in the current directory
    // But first, create the filename dynamically, in a static size buffer
    char output_file[PATH_MAX];
    if (access(DEVICE_OUTPUT_DIR, F_OK) == 0) {
        snprintf(output_file, PATH_MAX, "%s/%s", DEVICE_OUTPUT_DIR, OUTPUT_FILE);
    } else {
        snprintf(output_file, PATH_MAX, "./%s", OUTPUT_FILE);
    }

    fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);


    // Write header to file
    const char *header = "date time some_avg10 some_avg60 some_avg300 some_total full_avg10 full_avg60 full_avg300 full_total\n";
    write_to_file(fd, header);

    while (1) {
        proc_file = fopen(PROC_FILE, "r");
        if (proc_file == NULL) {
            perror("fopen");
            close(fd);
            exit(EXIT_FAILURE);
        }

        char some_avg10[16], some_avg60[16], some_avg300[16], some_total[16];
        char full_avg10[16], full_avg60[16], full_avg300[16], full_total[16];

        while (fgets(buffer, BUFFER_SIZE, proc_file) != NULL) {
            sscanf(buffer, "some avg10=%s avg60=%s avg300=%s total=%s",
                   some_avg10, some_avg60, some_avg300, some_total);
            fgets(buffer, BUFFER_SIZE, proc_file);
            sscanf(buffer, "full avg10=%s avg60=%s avg300=%s total=%s",
                   full_avg10, full_avg60, full_avg300, full_total);

            time(&rawtime);
            timeinfo = localtime(&rawtime);
            char timestamp[BUFFER_SIZE];
            strftime(timestamp, BUFFER_SIZE, "%Y-%m-%d %H:%M:%S", timeinfo);

            dprintf(fd, "%s %s %s %s %s %s %s %s %s\n", timestamp, some_avg10, some_avg60, some_avg300, some_total, full_avg10, full_avg60, full_avg300, full_total);
            fsync(fd);
        }

        fclose(proc_file);
        sleep(1);
    }

    close(fd);
    return 0;
}
