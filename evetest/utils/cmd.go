// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

// CommandOpt allows to modify Cmd config.
type CommandOpt func(cmd *exec.Cmd)

// SetCommandStdin sets the given string as the standard input for the command.
func SetCommandStdin(stdin string) CommandOpt {
	return func(cmd *exec.Cmd) {
		cmd.Stdin = strings.NewReader(stdin)
	}
}

// SetCommandEnvVars sets the given list of key=value strings as the environment
// variables for the command.
func SetCommandEnvVars(vars []string) CommandOpt {
	return func(cmd *exec.Cmd) {
		cmd.Env = vars
	}
}

// SetThisProcessStdin configures the command to inherit the current process's
// standard input (stdin). This is typically used for interactive commands
// that require user input.
func SetThisProcessStdin() CommandOpt {
	return func(cmd *exec.Cmd) {
		cmd.Stdin = os.Stdin
	}
}

// RunCommandForeground runs a command in the foreground, attaching its stdout
// and stderr to the current process and optionally applying command options.
// The command is terminated if the current process receives a termination
// signal (SIGINT, SIGTERM, SIGQUIT, or SIGHUP).
func RunCommandForeground(name string, args []string, opts ...CommandOpt) (err error) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	for _, opt := range opts {
		opt(cmd)
	}
	go func() {
		<-sigChan
		_ = cmd.Process.Kill()
	}()
	return cmd.Run()
}
