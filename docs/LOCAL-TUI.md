# TUI (Text User Interface) for the local operator

EVE has a user-friendly TUI (Text User Interface) that can be used to interact with the system.
The implementation is consists of two parts

1. Client application responsible for rendering the TUI, sending user input to the server, and handling asynchronous server notification. The client is written in Rust and hosted at [https://github.com/lf-edge/eve-monitor-rs](https://github.com/lf-edge/eve-monitor-rs). Corresponding Dockerfile and LinuxKit build files are located at `pkg/monitor`
2. Server part is implemented inside [pkg/pillar/cmd/monitor](../pkg/pillar/cmd/monitor/)

The client communicates with the server over UNIX socket

## TTY and serial console

The UI is rendered on a local TTY (/dev/tty2) only i.e. on a physical monitor attached to the system. Neither Serial Console nor SSH connection has access to TUI. It is done to ensure the physical presence of the operator.

## /dev/ttyX vs /dev/console vs /dev/tty0

There are three distinguishable console devices in Linux `/dev/console`, `/dev/tty0` and `/dev/ttyX` where X > 0. The latter points to a particular virtual terminal device i.e. a dedicated framebuffer for VGA console.  `/dev/tty0` points to *currently active* TTY device. This can be proven by reading `/sys/devices/virtual/tty/tty0/active` file. This file exists only for `/dev/tty0`. On the other hand `/dev/console` may point to several devices at a time. These are devices user specifies in `console=` kernel command line parameters. The list can be obtained by reading `/sys/devices/virtual/tty/console/active` file.

The user can switch between virtual terminals by using `Alt+Fx` or `Alt+<,>` keys. When the current TTY is set `/dev/tty0` tracks this change and always points to to the current terminal

Monitor application is spawned on a `/dev/tty2` using a `openvt` utility while the rest of the applications are spawned on the default kernel console defined by `console=` parameters on the kernel command line. When the application is in focus (`/dev/tty2` is an active console) writing to `/dev/console` or to `/dev/tty0` which points to the same device corrupts TUI thus it cannot be used by other services in the system to produce the output. At least when `/dev/tty2` is a current console.

On the other hand `/dev/tty`  (no digit at the end!) device always points to a TTY *in the context of running process*. This device can be used instead of `/dev/console` by other services for the output.

Mode details can be found in [https://www.kernel.org/doc/Documentation/admin-guide/serial-console.rst](https://www.kernel.org/doc/Documentation/admin-guide/serial-console.rst), [https://www.kernel.org/doc/html/v6.11/admin-guide/devices.html#virtual-consoles-and-the-console-device](https://www.kernel.org/doc/html/v6.11/admin-guide/devices.html#virtual-consoles-and-the-console-device) and in this blog post [https://www.baeldung.com/linux/monitor-keyboard-drivers](https://www.baeldung.com/linux/monitor-keyboard-drivers)

## Limitations of linux terminal

Rust application can be built and run on Linux host for testing and development purposes. When running on a host its terminal is used for rendering. Host terminals ( e.g. `TERM=xterm`) are very different in capabilities compared to the built in Linux terminal which is used for `/dev/ttyX` (`TERM=linux`) devices. The major differences important for monitor application are

* Number of supported colors.

  `linux` terminal can use only 8 colors for foreground and 8 colors for background colors. In contrast host terminals can easily display 256 colors and more

* Limited number of pseudo-graphics glyphs.

  These limitations can be relaxed by using a custom font with 256 glyphs compared to the standard one that uses 512 glyphs. In this case an extra bit can be used to render 16 colors. Besides, extra pseudo-graphics glyphs can be added instead of unused characters to display e.g. rounded boxes.

  As of now a standard font is used so the look of the application on the host and on EVE is different

* Key handling.

  By default `linux` terminal cannot properly handle many key combinations e.g. `PgDwn`, `Ctrl+left, Ctrl + right`, etc. A custom key map must be set to properly handle required combinations. It is done in [pkg/monitor/run-monitor.sh](../pkg/monitor/run-monitor.sh) by calling `loadkeys` utility

  As of now only `Ctrl + [left|right|up|down]` are properly handled.
