#include <unistd.h>
#include <sys/reboot.h>

int main() {
    reboot(RB_POWER_OFF); /* AKA LINUX_REBOOT_CMD_POWER_OFF AKA 0x4321fedc */
    return 0; /* this can never happen */
}
