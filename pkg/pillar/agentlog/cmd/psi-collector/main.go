// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log/syslog"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	//PIDFile is the file to store the PID
	PIDFile = types.MemoryMonitorDir + "/psi-collector/psi-collector.pid"
)

var log *base.LogObject

func createPIDFile() error {
	f, err := os.Create(PIDFile)
	if err != nil {
		log.Errorf("Failed to create PID file: %v", err)
		return err
	}
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf("%d", os.Getpid()))
	if err != nil {
		log.Errorf("Failed to write PID to file: %v", err)
		return err
	}
	return nil
}

func getPIDFromFile() (int, error) {
	f, err := os.Open(PIDFile)
	if err != nil {
		log.Errorf("Failed to open PID file: %v", err)
		return 0, err
	}
	defer f.Close()
	var pid int
	_, err = fmt.Fscanf(f, "%d", &pid)
	if err != nil {
		log.Errorf("Failed to read PID from file: %v", err)
		return 0, err
	}
	return pid, nil
}

func daemonize() error {

	// Check if the process is already daemonized by checking the environment variable
	if os.Getenv("DAEMONIZED") == "1" {
		return nil
	}

	//  If it's not daemonized, daemonize it

	log.Noticef("Starting Memory PSI Collector")

	filePath, err := os.Executable()
	if err != nil {
		log.Errorf("Failed to get executable path: %v", err)
		return err
	}
	args := os.Args
	env := os.Environ()
	// Add the daemon env variable to differentiate the daemon process
	env = append(env, "DAEMONIZED=1")
	// Open /dev/null for the child process
	devNull, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		log.Errorf("Failed to open /dev/null: %v", err)
		return err
	}
	forkAttr := &syscall.ProcAttr{
		// Files is the set of file descriptors to be duped into the child's
		Files: []uintptr{devNull.Fd(), devNull.Fd(), devNull.Fd()},
		Sys: &syscall.SysProcAttr{
			Setsid: true, // Create a new session to detach from the terminal
		},
		Env: env,
	}

	// Fork off the parent process
	_, err = syscall.ForkExec(filePath, args, forkAttr)
	if err != nil {
		log.Errorf("Failed to fork: %v", err)
		return err
	}
	os.Exit(0)
	return nil
}

func main() {

	// Create a logger
	logger := logrus.New()

	// Create a syslog writer
	syslogWriter, err := syslog.New(syslog.LOG_NOTICE|syslog.LOG_DAEMON, "psi-collector")
	if err != nil {
		fmt.Println("Failed to create syslog writer: ", err)
		os.Exit(1)
	}
	// Set the output of the logger to the syslog writer
	logger.SetOutput(syslogWriter)

	// Create a log object
	log = base.NewSourceLogObject(logger, "psi-collector", os.Getpid())

	// Check if the collector is already running
	if _, err := os.Stat(PIDFile); err == nil {
		savedPid, err := getPIDFromFile()
		if err != nil {
			log.Errorf("Failed to get PID from file: %v", err)
			return
		}
		if savedPid != os.Getpid() {
			log.Errorf("Memory PSI Collector is already running with PID: %d", savedPid)
			return
		}
	}

	err = daemonize()
	if err != nil {
		log.Errorf("Failed to daemonize: %v", err)
		return
	}

	// Create a PID file
	err = createPIDFile()
	if err != nil {
		log.Errorf("Failed to create PID file: %v", err)
		return
	}
	defer os.Remove(PIDFile)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-signalChan
		os.Remove(PIDFile)
		log.Noticef("Memory PSI Collector stopped")
		os.Exit(0)
	}()

	err = agentlog.MemoryPSICollector(context.Background(), log)
	if err != nil {
		log.Errorf("MemoryPSICollector failed: %v", err)
	}
}
