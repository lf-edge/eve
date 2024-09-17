// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"github.com/creack/pty"
)

type edgeviewRun struct {
	cmd     *exec.Cmd
	ctx     context.Context
	cancel  func()
	path    string
	port    uint16
	tty     *os.File
	started atomic.Bool
}

func pathToScript(path string) string {
	scripts, err := filepath.Glob(path)
	if err != nil {
		log.Fatalf("could not glob '%s': %v", path, err)
	}

	newestScript := ""
	newestTime := time.Unix(0, 0)
	for _, script := range scripts {
		st, err := os.Stat(script)
		if err != nil {
			continue
		}

		if st.ModTime().After(newestTime) {
			newestTime = st.ModTime()
			newestScript = script
		}
	}

	return newestScript
}

func (er *edgeviewRun) enablePprof() error {
	edgeviewParam := "pprof/on"

	// see ../../pkg/edgeview/src/system.go:68
	matchOutput := "=== System: <pprof/on> ==="

	_, err := er.runEdgeview(edgeviewParam, matchOutput)
	if err != nil {
		return err
	}

	return nil
}

func (er *edgeviewRun) disablePprof() error {
	edgeviewParam := "pprof/off"
	// see ../../pkg/edgeview/src/system.go:68
	matchOutput := "=== System: <pprof/off> ==="

	_, err := er.runEdgeview(edgeviewParam, matchOutput)
	if err != nil {
		return err
	}

	return nil
}

func (er *edgeviewRun) stopHTTPDebugPort() {
	_, err := er.tty.Write([]byte{'\x03'})
	if err != nil {
		_, ok := err.(*fs.PathError)
		if !ok {
			log.Printf("could not send ctrl+c: %v", err)
		}
	}
	if er.cmd != nil {
		_ = er.cmd.Process.Signal(os.Interrupt)
	}

	if er.cancel != nil {
		er.cancel()
		er.ctx = nil
		er.port = 0
	}
	if er.cmd != nil {
		err = er.cmd.Wait()
		if err != nil {
			exitErr, ok := err.(*exec.ExitError)
			if ok {
				status := exitErr.Sys().(syscall.WaitStatus)
				if !status.Signaled() {
					log.Printf("expected that the process exited because of signal, but %v", err)
				}
			} else if !strings.Contains(err.Error(), "Wait was already called") {
				log.Printf("waiting failed: %v/%T", err, err)
			}
		}
	}
	err = er.tty.Close()
	if err != nil {
		_, ok := err.(*fs.PathError)
		if !ok {
			log.Printf("closing tty failed: %v", err)
		}
	}

	if er.cmd != nil {
		_ = er.cmd.Process.Kill()
		er.cmd = nil
	}
}

func (er *edgeviewRun) forwardHTTPDebugPort() error {
	var err error

	hostForward := "localhost:6543"
	er.ctx, er.cancel = context.WithTimeout(context.Background(), 5*time.Minute)
	er.cmd = exec.CommandContext(er.ctx, "bash", er.path, fmt.Sprintf("tcp/%s", hostForward))

	er.tty, err = pty.Start(er.cmd)
	if err != nil {
		log.Fatalf("starting pty for cmd (%v) failed: %v", er.cmd, err)
	}

	matchedChan := make(chan struct{})

	var forwardLine string
	var output string
	go func() {
		scanner := bufio.NewScanner(er.tty)
		for scanner.Scan() {
			line := scanner.Text()
			output += line + "\n"

			if strings.Contains(line, hostForward) {
				forwardLine = strings.TrimFunc(line, func(r rune) bool {
					return !unicode.IsGraphic(r)
				})
				close(matchedChan)
			}
		}
	}()

	select {
	case <-er.ctx.Done():
		return nil
	case <-matchedChan:
	}

	er.port, err = matchEdgeviewIPOutput(forwardLine)
	if err != nil {
		return fmt.Errorf("could not match output - output was: %s, err is: %v", output, err)
	}

	return nil
}

func matchEdgeviewIPOutput(line string) (uint16, error) {
	rex := regexp.MustCompile(`(\S+) -> `)
	matches := rex.FindStringSubmatch(line)
	if len(matches) != 2 {
		return 0, fmt.Errorf("could not match '%s'", line)
	}
	_, portString, err := net.SplitHostPort(matches[1])
	if err != nil {
		return 0, fmt.Errorf("could not extract port from '%s': %v", matches[1], err)
	}

	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("could not convert %s to int: %v", portString, err)
	}

	return uint16(port), nil
}

func (er *edgeviewRun) runEdgeview(edgeviewParam string, matchOutput string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", er.path, edgeviewParam)

	tty, err := pty.Start(cmd)
	if err != nil {
		log.Fatalf("starting pty for cmd (%v) failed: %v", cmd, err)
	}

	defer tty.Close()

	scanner := bufio.NewScanner(tty)
	success := false
	var output string
	for scanner.Scan() {
		line := scanner.Text()
		output += line + "\n"

		if strings.Contains(line, matchOutput) {
			success = true
		}
	}
	if !success {
		return "", fmt.Errorf("%s failed, output was:\n%s", edgeviewParam, output)
	}

	err = cmd.Wait()
	if err != nil {
		return "", fmt.Errorf("waiting for cmd (%v) failed: %v", cmd, err)
	}
	return output, nil
}

func (er *edgeviewRun) start(evScript string) (uint16, error) {
	var err error

	if er.started.Swap(true) {
		return 0, fmt.Errorf("edgeview already started")
	}

	er.path = pathToScript(evScript)
	for i := 0; i < 5; i++ {
		err = er.enablePprof()
		if err == nil {
			break
		}
	}
	if err != nil {
		return 0, fmt.Errorf("could not enable pprof: %v", err)
	}

	err = er.forwardHTTPDebugPort()
	if err != nil {
		return 0, fmt.Errorf("could not forward http port: %v", err)
	}

	return er.port, nil
}

func (er *edgeviewRun) shutdown() {
	er.stopHTTPDebugPort()
	time.Sleep(5 * time.Second)
	err := er.disablePprof()
	if err != nil {
		log.Fatalf("could not disable pprof: %v", err)
	}
	// give edgeview some time ...
	time.Sleep(5 * time.Second)
}
