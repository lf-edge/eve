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
