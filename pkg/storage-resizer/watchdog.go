// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

// The `run-watchdog` subcommand keeps the hardware watchdog fed across a long
// offline operation. It is meant to be started in the background by the
// orchestrator of that operation (storage-init around the boot-disk resize
// today; the installer later) and killed when the operation finishes — on the
// terminating signal it disarms the watchdog (magic close). This keeps the
// watchdog handling in ONE place that every long-running early-boot step can
// reuse, rather than each re-implementing it.
//
// Why it is needed: a watchdog the firmware armed at power-on is fed by the
// kernel only until /dev/watchdog is first opened or `open_timeout` elapses;
// once a userspace process owns the device it must pet it or the device resets.
// An offline shrink/grow (or install) can run longer than the watchdog timeout,
// so the owning process must keep petting.
//
// --no-pet holds the device open but never pets: a test-only mode that
// demonstrates the watchdog firing when petting is absent.

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// watchdogDevice is the Linux hardware-watchdog character device (a var so tests
// can point it elsewhere).
var watchdogDevice = "/dev/watchdog"

// cmdRunWatchdog opens /dev/watchdog, sets its timeout, and pets it until
// terminated by a signal.
func cmdRunWatchdog(args []string) int {
	fs := flag.NewFlagSet("run-watchdog", flag.ExitOnError)
	timeout := fs.Int("timeout", 30, "hardware watchdog timeout in seconds")
	interval := fs.Duration("interval", 0, "pet interval (default: timeout/3, min 2s)")
	noPet := fs.Bool("no-pet", false, "hold the watchdog open but do NOT pet it (test only: demonstrates a fire)")
	_ = fs.Parse(args)

	f, err := os.OpenFile(watchdogDevice, os.O_WRONLY, 0)
	if err != nil {
		// No watchdog (plain qemu without the chipset device, or host-side use):
		// nothing to feed. Exit 0 so the caller's operation proceeds rather than
		// failing for lack of a watchdog.
		fmt.Fprintf(os.Stderr, "run-watchdog: no %s (%v); nothing to feed\n", watchdogDevice, err)
		return 0
	}
	fd := int(f.Fd())
	// Best effort: not all drivers honor SETTIMEOUT; read back what stuck.
	_ = unix.IoctlSetPointerInt(fd, unix.WDIOC_SETTIMEOUT, *timeout)
	eff, _ := unix.IoctlGetInt(fd, unix.WDIOC_GETTIMEOUT)

	// Terminate (and disarm) on the signals the orchestrator sends to stop us.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM, syscall.SIGINT)

	if *noPet {
		fmt.Fprintf(os.Stderr, "run-watchdog: holding %s timeout=%ds WITHOUT petting (test) — it will reset the device\n", watchdogDevice, eff)
		<-sigc
		// Deliberately no magic 'V': leave it armed so the test's point stands.
		_ = f.Close()
		return 0
	}

	iv := *interval
	if iv <= 0 {
		iv = time.Duration(eff) * time.Second / 3
		if iv < 2*time.Second {
			iv = 2 * time.Second
		}
	}
	fmt.Fprintf(os.Stderr, "run-watchdog: feeding %s every %s (timeout=%ds)\n", watchdogDevice, iv, eff)
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		_, _ = f.Write([]byte{0}) // any byte other than a lone 'V' is a keepalive
		select {
		case <-sigc:
			_, _ = f.Write([]byte("V")) // magic close: disarm
			_ = f.Close()
			return 0
		case <-t.C:
		}
	}
}
