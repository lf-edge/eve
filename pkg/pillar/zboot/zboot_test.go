// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package zboot

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

func findExePath(exe string) string {
	pathEnv := os.Getenv("PATH")

	paths := strings.Split(pathEnv, ":")

	for _, path := range paths {
		fullPath := filepath.Join(path, exe)
		_, err := os.Stat(fullPath)
		if err == nil {
			return fullPath
		}
	}

	return ""
}

// let's do our own pkill, as handling different versions of it is a pain
// f.e. procps pkill needs '-f' if the string is longer than 15 characters
// but busybox pkill doesn't work with '-f'
func pkill(path string) bool {
	dirEntries, err := os.ReadDir("/proc")
	if err != nil {
		panic(err)
	}

	for _, dirEntry := range dirEntries {
		var pid int
		pidString := filepath.Base(dirEntry.Name())
		if pid, err = strconv.Atoi(pidString); err != nil {
			continue
		}
		cmdlinePath := filepath.Join("/proc", dirEntry.Name(), "cmdline")
		cmdline, err := os.ReadFile(cmdlinePath)
		if err != nil {
			continue
		}
		exe := string(bytes.Split(cmdline, []byte{0})[0])
		if len(exe) == 0 {
			continue
		}
		if path != exe {
			continue
		}

		syscall.Kill(pid, syscall.SIGUSR2)
		return true
	}

	return false
}

func TestGetConfigPartitionDevname(t *testing.T) {
	tests := []struct {
		name    string
		zboot   string // body of the fake zboot script put first on PATH
		wantDev string
		wantErr bool
	}{
		{
			name: "CONFIG on the boot disk",
			zboot: `[ "$*" = "partdev CONFIG" ] && { echo /dev/vdb4; exit 0; }
exit 1`,
			wantDev: "/dev/vdb4",
		},
		{name: "zboot fails", zboot: "exit 1", wantErr: true},
		{name: "no CONFIG on the boot disk", zboot: "exit 0", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			script := "#!/bin/sh\n" + tt.zboot + "\n"
			if err := os.WriteFile(filepath.Join(dir, "zboot"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

			dev, err := GetConfigPartitionDevname()
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if dev != tt.wantDev {
				t.Fatalf("got %q, want %q", dev, tt.wantDev)
			}
		})
	}
}

func TestWithConfigPartitionRWNoPartition(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "zboot"), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	called := false
	err := WithConfigPartitionRW(func(string) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("expected an error when the CONFIG partition cannot be found")
	}
	if called {
		t.Fatal("fn must not run without a mounted CONFIG partition")
	}
}

func TestExecWithRetry(t *testing.T) {
	t.Parallel()

	logger := logrus.New()
	logBuf := &bytes.Buffer{}
	logger.Out = logBuf
	log := base.NewSourceLogObject(logger, "zboot_test", -255)
	data, err := os.ReadFile(findExePath("sleep"))
	if err != nil {
		panic(err)
	}
	tmpDir, err := os.MkdirTemp("/tmp", "sleep-TestExecWithRetry")
	defer os.RemoveAll(tmpDir)
	tmpFile := filepath.Join(tmpDir, "sleep")
	err = os.WriteFile(tmpFile, data, 0700)
	if err != nil {
		panic(err)
	}

	var pkillOutput []byte
	go func() {
		for !pkill(tmpFile) {
			time.Sleep(1 * time.Second)
		}
		// remove the binary, otherwise execWithRetry would retry endlessly
		os.Remove(tmpFile)
	}()

	_, err = execWithRetry(log, tmpFile, "60")
	if err != nil {
		t.Log(err)
	}

	logOutput := logBuf.String()

	if !strings.Contains(logOutput, "because of signal user defined signal 2") {
		t.Fatalf("Killed sleep with USR2 went unnoticed, pkill output is: %s", string(pkillOutput))
	}
	t.Log(logBuf.String())
}
