// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package instances

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// A terminal "remembers" its chosen instance in a file keyed by the terminal's
// session id, i.e. the pid of the session leader (normally the login shell of
// that terminal window or tmux pane). A CLI process cannot modify the
// environment of its parent shell, and this needs no shell integration. The
// leader's start time is stored too, so that a record left behind by a closed
// terminal is ignored when its pid gets reused.

type sessionRecord struct {
	SID      int      `json:"sid"`
	SIDStart string   `json:"sidStart"`
	Instance Instance `json:"instance"`
}

func sessionsDir() string {
	return filepath.Join(Home(), "sessions")
}

// sessionKey identifies the current terminal session. ok is false when there
// is no controlling terminal (scripts, CI), in which case nothing is
// remembered.
func sessionKey() (sid int, start string, ok bool) {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return 0, "", false
	}
	_ = tty.Close()
	sid, err = unix.Getsid(0)
	if err != nil || sid <= 0 {
		return 0, "", false
	}
	start, err = processStartTime(sid)
	if err != nil {
		return 0, "", false
	}
	return sid, start, true
}

func processStartTime(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err == nil {
		// The command name (field 2) may contain spaces and parentheses, so
		// skip past its closing parenthesis. start time is field 22, i.e. the
		// 20th field after the command name.
		s := string(data)
		idx := strings.LastIndex(s, ")")
		if idx < 0 {
			return "", errors.New("malformed /proc stat")
		}
		fields := strings.Fields(s[idx+1:])
		if len(fields) < 20 {
			return "", errors.New("malformed /proc stat")
		}
		return fields[19], nil
	}
	// No procfs (e.g. macOS).
	out, err := exec.Command("ps", "-o", "lstart=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func sessionPath(sid int) string {
	return filepath.Join(sessionsDir(), strconv.Itoa(sid)+".json")
}

// Remembered returns the instance chosen earlier in this terminal, if any.
// Records of terminals which no longer exist are removed on the way.
func Remembered() (Instance, bool) {
	sid, start, ok := sessionKey()
	if !ok {
		return Instance{}, false
	}
	pruneSessions()
	data, err := os.ReadFile(sessionPath(sid))
	if err != nil {
		return Instance{}, false
	}
	var rec sessionRecord
	if json.Unmarshal(data, &rec) != nil || rec.SIDStart != start {
		_ = os.Remove(sessionPath(sid))
		return Instance{}, false
	}
	return rec.Instance, true
}

// Remember stores the instance as the choice of this terminal. It returns
// false if the terminal cannot be identified (no controlling terminal).
func Remember(inst Instance) (bool, error) {
	sid, start, ok := sessionKey()
	if !ok {
		return false, nil
	}
	if err := os.MkdirAll(sessionsDir(), 0o700); err != nil {
		return false, err
	}
	data, err := json.Marshal(sessionRecord{SID: sid, SIDStart: start, Instance: inst})
	if err != nil {
		return false, err
	}
	return true, os.WriteFile(sessionPath(sid), data, 0o600)
}

// Forget drops the instance remembered by this terminal.
func Forget() {
	if sid, _, ok := sessionKey(); ok {
		_ = os.Remove(sessionPath(sid))
	}
}

// pruneSessions removes records whose terminal session leader is gone.
func pruneSessions() {
	entries, err := os.ReadDir(sessionsDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		sid, err := strconv.Atoi(strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(sessionsDir(), e.Name()))
		if err != nil {
			continue
		}
		var rec sessionRecord
		start, startErr := processStartTime(sid)
		if json.Unmarshal(data, &rec) != nil || startErr != nil || rec.SIDStart != start {
			_ = os.Remove(filepath.Join(sessionsDir(), e.Name()))
		}
	}
}
