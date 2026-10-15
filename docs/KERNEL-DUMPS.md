# Kernel panic records in EVE-OS

EVE-OS records a kernel panic with pstore: the panicking kernel writes the tail
of its log to firmware storage, and on the next boot nodeagent turns the newest
panic into the reboot reason and stack reported to the controller. There is no
crash kernel, no `crashkernel=` memory reservation and no vmcore.

## What the kernel writes

On a panic, or an oops (EVE sets `CONFIG_PANIC_ON_OOPS`), `kmsg_dump` hands the
log to pstore, which stores it from the newest end backwards in records of the
backend's size until `pstore.kmsg_bytes` (10240) compressed bytes are written.
That is about 25 KB of log, enough for the panic message and the whole call
trace.

The backend depends on the platform:

| Platform | Backend | Files in `/sys/fs/pstore` |
|---|---|---|
| UEFI | efi-pstore: one EFI variable per record | `dmesg-efi_pstore-<id>` |
| ACPI ERST (many servers) | ERST | `dmesg-erst-<id>` |

Each record starts with a line `<reason>#<count> Part<n>`, where Part1 holds the
newest part of the log, and the file's mtime is the time it was written. A
record the running kernel cannot decompress appears with an `.enc.z` suffix.
Deleting a file erases the record from firmware storage.

Firmware storage is small. OVMF's 256 KB variable store holds about 20 panics;
the kernel then refuses further writes rather than fill it, so the first panics
of a loop are kept and later ones are not recorded. Platforms with neither
backend, and hangs that end in a watchdog reset, leave no record.

## What EVE does on the next boot

Before it handles the reboot reason, nodeagent reads `/sys/fs/pstore` (through
`/hostfs`) and:

1. Groups the records into dumps and reassembles each dump's log.
2. Treats a dump as current if it was written after the previous boot reached
   nodeagent (the mtime of `/persist/status/restartcounter`), and as stale
   otherwise, for example records left by an EVE version without this reader.
3. Logs every dump the way a Go fatal stack trace is logged: an error
   `Kernel panic stack trace from pstore (Panic#1 at <time>, …)` with the panic
   message, each line of the kernel log as `[kernel panic #N]: <line>` on a log
   object of type `kernel_panic_stacks`, and `Kernel panic stack trace: end of
   stack`. Dumps written for another reason (`Shutdown`, `Emergency`) are
   logged as `Kernel log dump` at warning level.
4. Saves every dump, all of its records reassembled into one file, to
   `/persist/kcrashes/pstore-<time>.log`, keeping the 10 newest dumps. Records
   the kernel cannot decompress are copied under their own names and do not
   count toward that limit, since they cannot be grouped into dumps.
5. If the newest current dump is a panic or an oops, writes
   `/persist/reboot-reason`, `/persist/reboot-stack` and `/persist/boot-reason`
   with the time of the panic:

   | `/persist/reboot-reason` already present | Reboot reason | Boot reason |
   |---|---|---|
   | No | "kernel panic, pstore: \<panic message\>" | `BootReasonKernel` |
   | Yes, with `BootReasonKernel` | The stored files stand | |
   | Yes, older than the panic | "kernel panic after \<stored reason\>" | The stored one |
   | Yes, newer than the panic | The stored files stand | |

   More than one current panic adds "(N panics)" to the reason.

   A reason older than the panic means EVE was already rebooting when the
   kernel panicked, for example a driver that panics on shutdown after the
   watchdog or a reboot command decided to reboot. The boot reason stays the one
   EVE wrote, because zedagent picks the configuration to start from by it: after
   a watchdog or fatal-error reboot it starts from the backup configuration to
   avoid a reboot loop, and a panic on the way down must not change that. The
   panic stack replaces `/persist/reboot-stack`; a Go stack stored there is also
   in `/persist/log/reboot-stack.log`.
6. Erases each record whose dump now has a durable copy on `/persist`.

The controller then receives `lastRebootReason`, `lastBootReason`
(`BOOT_REASON_KERNEL` unless EVE was already rebooting) and, as
`lastRebootStack`, the log from the "Kernel
panic - not syncing" line onward, cut to its first 1600 characters. A dump
without that line, such as an oops that did not panic, sends the last 1600
characters instead. If the device reboots before that, the next boot logs the
reboot stack from `/persist/reboot-stack` as `[dmesg #N]` lines instead.

To find kernel panics in the device log, search for `kernel_panic_stacks` or
`Kernel panic stack trace`.

## Testing

`echo c > /proc/sysrq-trigger` panics the kernel. After the reboot (120 seconds
later, per `panic=120`), check the reboot reason at the controller, the
`/persist/kcrashes/pstore-*.log` file, and that `/sys/fs/pstore` is empty.
