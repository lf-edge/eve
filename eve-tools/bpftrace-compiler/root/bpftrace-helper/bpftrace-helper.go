// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func allWriter() *os.File {
	writers := make([]*os.File, 0)

	devs := []string{
		"ttyS0",
		"vc0",
		"console",
		"tty0",
		"ttyAMA0",
		"tty0",
		"TCU0",
		"THS0",
		"ttymxc0",
	}

	for _, dev := range devs {
		devPath := filepath.Join("/dev", dev)
		fh, err := os.OpenFile(devPath, os.O_WRONLY, 0666)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "Open %s: %v\n", dev, err)
			continue
		}

		if fh != nil {
			writers = append(writers, fh)
		}
	}

	_, f := newMultiFileWriter(writers)
	return f

}

func symlinkBusyboxApplet(cmd string) {
	dest := filepath.Join("/bin", cmd)
	err := os.Symlink("/usr/bin/busybox", dest)
	if err != nil {
		log.Printf("Link /usr/bin/busybox -> %s: %+v", dest, err)
	}
}

func mountFilesystems() {
	mounts := []struct {
		from   string
		to     string
		fstype string
	}{
		{
			from:   "tmpfs",
			to:     "/bin",
			fstype: "tmpfs",
		},
		{
			from:   "proc",
			to:     "/proc",
			fstype: "proc",
		},
		{
			from:   "none",
			to:     "/sys",
			fstype: "sysfs",
		},
		{
			from:   "none",
			to:     "/sys/kernel/tracing",
			fstype: "tracefs",
		},
		{
			from:   "9pmount",
			to:     "/mnt",
			fstype: "9p",
		},
	}

	for _, mount := range mounts {
		err := syscall.Mount(mount.from, mount.to, mount.fstype, syscall.MS_SILENT, "")
		if err != nil {
			log.Printf("Mount %s failed: %+v", mount.to, err)
		}
	}
}

func containerRootFSMounts() {
	containersServicesDir := "/containers/services"
	serviceDirs, err := os.ReadDir(containersServicesDir)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		log.Printf("readdir of /containers/services failed: %v", err)
	}

	for _, serviceDir := range serviceDirs {
		var err error

		lowerDir := filepath.Join(containersServicesDir, serviceDir.Name(), "lower")
		rootfsDir := filepath.Join(containersServicesDir, serviceDir.Name(), "rootfs")

		_, err = os.Stat(lowerDir)
		if err != nil {
			continue
		}
		_, err = os.Stat(rootfsDir)
		if err != nil {
			continue
		}

		err = syscall.Mount(lowerDir, rootfsDir, "", syscall.MS_SILENT|syscall.MS_BIND, "")
		if err != nil {
			log.Printf("could not bind mount %s -> %s: %v", lowerDir, rootfsDir, err)
		}
	}

}

func main() {
	var err error

	err = syscall.Mount("devtmpfs", "/dev", "devtmpfs", syscall.MS_SILENT, "")
	if err != nil {
		syscallErrnoErr, ok := err.(syscall.Errno)
		if !ok || syscallErrnoErr != syscall.EBUSY {
			// if CONFIG_DEVTMPFS_MOUNT=y is set, then the kernel already has mounted it, so ignore
			fmt.Fprintf(os.Stderr, "Mount /dev failed: %+v %T\n", err, err)
		}
	}

	outputFh := allWriter()

	log.SetOutput(outputFh)

	log.Printf("LOG STARTING")

	mountFilesystems()
	containerRootFSMounts()

	cmdlineBytes, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		log.Printf("Readfile /proc/cmdline: %+v", err)
	}
	var units []string
	for _, cmdArgBytes := range bytes.Split(cmdlineBytes, []byte{' '}) {
		cmdArg := string(cmdArgBytes)
		cmdArg = strings.TrimSpace(cmdArg)
		prefix := "units="
		if !strings.HasPrefix(cmdArg, prefix) {
			continue
		}
		units = strings.Split(strings.TrimPrefix(cmdArg, prefix), ",")
	}
	if len(units) == 0 {
		units = []string{"shell"}
	}

	err = os.Chdir("/mnt")
	if err != nil {
		log.Printf("Chdir /mnt: %+v", err)
	}

	err = os.Remove("/mnt/temp_btaot")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Print("Could not remove /mnt/temp_btoaot")
	}

	symlinkBusyboxApplet("sh")

	for _, unit := range units {
		if unit == "compile" {
			bpftraceCompileUnit()
		}
		if unit == "shell" {
			shellUnit()
		}
		if unit == "list" {
			bpftraceListKernelUnit()
		}
		if strings.HasPrefix(unit, "list@") {
			split := strings.SplitN(unit, "@", 2)
			if len(split) != 2 {
				log.Printf("could not parse %s", unit)
				break
			}
			bpftraceListUserspaceUnit(split[1])
		}
	}

	powerdownUnit()
}

func shellUnit() {
	var err error
	for _, cmd := range []string{"ls", "cp", "mv", "cat", "file", "mount", "umount", "find", "strings"} {
		symlinkBusyboxApplet(cmd)
	}
	syscall.Exec("/bin/sh", []string{"/bin/sh"}, []string{"PATH=/bin:/usr/bin"})
	if err != nil {
		log.Fatalf("Exec /bin/sh: %+v", err)
	}
}

func powerdownUnit() {
	var err error

	err = os.Chdir("/")
	if err != nil {
		log.Printf("Chdir /: %+v", err)
	}

	err = syscall.Unmount("/mnt", 0)
	if err != nil {
		log.Fatalf("Umount: %+v", err)
	}

	err = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	if err != nil {
		fmt.Println("Could not shutdown, please shut down manually :-(")
	}
}

func bpftraceListUserspaceUnit(binary string) {
	_, err := os.Stat(binary)
	if err != nil {
		log.Printf("could not stat %s: %v", binary, err)
	}
	bpftraceArgs := []string{
		"-l",
		fmt.Sprintf("u:%s:*", binary),
	}
	runBpftraceUnitWithArgs(bpftraceArgs)
}

func bpftraceListKernelUnit() {
	bpftraceArgs := []string{"-l"}
	runBpftraceUnitWithArgs(bpftraceArgs)
}

func runBpftraceUnitWithArgs(bpftraceArgs []string) {
	var err error

	stdoutFh, err := os.Create("/mnt/stdout.txt")
	if err != nil {
		log.Printf("could not open /mnt/stdout.txt: %v", err)
		return
	}
	defer stdoutFh.Close()

	stderrFh, err := os.Create("/mnt/stderr.txt")
	if err != nil {
		log.Printf("could not open /mnt/stderr.txt: %v", err)
		return
	}
	defer stderrFh.Close()

	cmd := exec.Command("/usr/bin/bpftrace", bpftraceArgs...)
	cmd.Stdout = stdoutFh
	cmd.Stderr = stderrFh
	err = cmd.Run()
	if err != nil {
		log.Printf("Cmd Run: %+v", err)
	}
}

func bpftraceCompileUnit() {
	var err error
	cmdStdoutBuf := bytes.Buffer{}
	cmdStderrBuf := bytes.Buffer{}
	cmd := exec.Command("/usr/bin/bpftrace", "--aot", "/dev/null", "/mnt/bpf.bt")
	cmd.Env = []string{"PATH=/bin:/usr/bin", "LD_LIBRARY_PATH=/lib:/usr/lib:/usr/lib64"}
	cmd.Stdout = &cmdStdoutBuf
	cmd.Stderr = &cmdStderrBuf

	err = cmd.Run()
	if err != nil {
		log.Printf("Cmd Run: %+v", err)
	}

	err = os.Rename("/mnt/temp_btaot", "/mnt/bpf.aot")
	if err != nil {
		log.Printf("Rename failed: %+v\nbpftrace output was: %s\nStderr: %s\n", err, cmdStdoutBuf.String(), cmdStderrBuf.String())
	}

}
