// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Exec call wrapper for pillar agents.

package base

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"time"
)

const (
	/*
	 * execution timeout is supposed to be less than the watchdog timeout,
	 * as otherwise the watchdog might fire and reboot the system before
	 * the timeout fires
	 * exceptions are when an executable is started from a different goroutine
	 * source of the error timeout and the watchdog timeout:
	 * error timeout: $ grep -r errorTime pkg/pillar/cmd/ | grep time
	 * watchdog timeout: $ grep hv_watchdog_timer pkg/grub/rootfs.cfg
	 */
	timeoutLimit   = 3 * time.Minute
	defaultTimeout = 100 * time.Second
)

// Command holds the necessary data to execute command
type Command struct {
	command    *exec.Cmd
	log        *LogObject
	agentName  string
	timeout    time.Duration
	buffer     *bytes.Buffer
	ctx        context.Context
	errorMonad error
}

// Output runs the command and returns its standard output.
// Any returned error will usually be of type *ExitError.
// Waits for the exec call to finish for `defaultTimeout` after which timeout error is returned
func (c *Command) Output() ([]byte, error) {
	var buf bytes.Buffer
	c.command.Stdout = &buf
	c.buffer = &buf
	if c.timeout == 0 {
		c.timeout = defaultTimeout
	}
	return c.execCommand()
}

// CombinedOutput runs the command and returns its combined standard output and standard error.
// Waits for the exec call to finish for `defaultTimeout` after which timeout error is returned
func (c *Command) CombinedOutput() ([]byte, error) {
	var buf bytes.Buffer
	c.command.Stdout = &buf
	c.command.Stderr = &buf
	c.buffer = &buf
	if c.timeout == 0 {
		c.timeout = defaultTimeout
	}
	return c.execCommand()
}

func (c *Command) execCommand() ([]byte, error) {
	if c.errorMonad != nil {
		return nil, c.errorMonad
	}

	if c.log != nil {
		c.log.Tracef("execCommand(%v)", c.command.Args)
	}
	if err := c.command.Start(); err != nil {
		return nil, fmt.Errorf("execCommand(%v): error while starting command: %s", c.command.Args, err.Error())
	}

	// Use a channel to signal completion so we can use a select statement
	done := make(chan error)
	go func() { done <- c.command.Wait() }()
	stillRunning := time.NewTicker(25 * time.Second)
	defer stillRunning.Stop()

	waitTimer := time.NewTimer(c.timeout)
	defer waitTimer.Stop()

	if c.ctx == nil {
		c.ctx = context.Background()
	}

	for {
		select {
		case <-c.ctx.Done():
			// context cancelled, kill the process
			c.command.Process.Kill()
			return nil, fmt.Errorf("execCommand(%v): context cancelled", c.command.Args)
		case <-waitTimer.C:
			// Timeout happened first, kill the process.
			c.command.Process.Kill()
			return nil, fmt.Errorf("execCommand(%v): command timed out", c.command.Args)
		case err := <-done:
			// Command completed before timeout.
			return c.buffer.Bytes(), err
		case <-stillRunning.C:
		}
		updateAgentTouchFile(c.log, c.agentName)
	}
}

// WithLimitedTimeout set custom timeout for command
func (c *Command) WithLimitedTimeout(timeout time.Duration) *Command {
	c.timeout = timeout
	if c.timeout > timeoutLimit {
		c.errorMonad = fmt.Errorf("custom timeout (%v) is longer than watchdog timeout (%v)", c.timeout, defaultTimeout)
	}

	return c
}

// WithUnlimitedTimeout set custom timeout for command not bound to any limits for when run in a separate goroutine
func (c *Command) WithUnlimitedTimeout(timeout time.Duration) *Command {
	c.timeout = timeout

	return c
}

// WithContext set context for command
func (c *Command) WithContext(ctx context.Context) *Command {
	c.ctx = ctx
	return c
}

// Exec returns Command object
func Exec(log *LogObject, command string, arg ...string) *Command {
	return &Command{
		command:   exec.Command(command, arg...),
		log:       log,
		agentName: getAgentName(),
	}
}

// updateAgentTouchFile updates agent's touch file under /run/
func updateAgentTouchFile(log *LogObject, agentName string) {
	if agentName == "" {
		if log != nil {
			log.Warnf("updateAgentTouchFile: agentName is empty")
		}
		return
	}
	filename := fmt.Sprintf("/run/%s.touch", agentName)
	_, err := os.Stat(filename)
	if err != nil {
		file, err := os.Create(filename)
		if err != nil {
			if log != nil {
				log.Functionf("updateAgentTouchFile: %s\n", err)
			}
			return
		}
		file.Close()
	}
	_, err = os.Stat(filename)
	if err != nil {
		if log != nil {
			log.Errorf("updateAgentTouchFile: %s\n", err)
		}
		return
	}
	now := time.Now()
	err = os.Chtimes(filename, now, now)
	if err != nil {
		if log != nil {
			log.Errorf("updateAgentTouchFile: %s\n", err)
		}
		return
	}
}

// getAgentName parses stacktrace and returns involved agent under /pillar/cmd.
func getAgentName() string {
	stackTrace := strings.Split(string(debug.Stack()), "\n")
	var methodName, file, agent, resultAgentName string
	for i, trace := range stackTrace {
		if strings.HasPrefix(trace, "github.com/lf-edge/eve/pkg/pillar/cmd/") {
			trace = strings.TrimPrefix(trace, "github.com/lf-edge/eve/pkg/pillar/cmd/")
			start := strings.Index(trace, ".")
			end := strings.Index(trace, "(")
			if start > -1 && end > -1 {
				methodName = strings.TrimSpace(trace[start+1 : end])
				agent = strings.TrimSpace(trace[:start])
			}
			filePath := strings.TrimSpace(stackTrace[i+1])
			start = strings.LastIndex(filePath, "/")
			end = strings.Index(filePath, ":")
			if start > -1 && end > -1 {
				file = strings.TrimSpace(filePath[start+1 : end])
			}
			break
		}
	}
	switch agent {
	case "zedagent":
		switch file {
		case "handlecertconfig.go":
			if methodName == "getCertsFromController" || methodName == "parseControllerCerts" {
				resultAgentName = "zedagentccerts"
			} else {
				resultAgentName = "zedagentattest"
			}
		case "reportinfo.go":
			resultAgentName = "zedagentdevinfo"
		case "handlemetrics.go":
			resultAgentName = "zedagentmetrics"
		case "handleconfig.go":
			resultAgentName = "zedagentconfig"
		default:
			resultAgentName = "zedagent"
		}
	case "volumemgr":
		switch file {
		case "handlediskmetrics.go":
			resultAgentName = "volumemgrmetrics"
		default:
			resultAgentName = "volumemgr"
		}

	default:
		resultAgentName = agent
	}
	return resultAgentName
}
