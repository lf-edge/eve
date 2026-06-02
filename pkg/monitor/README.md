By default in modern kernels, non-root users are not allowed to read /dev/kmsg. But it is desirable for this application
to be able to read it for printing those logs for operators. To enable that functionality without running this as root
run `sudo sysctl kernel.dmesg_restrict=0`