// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

const (
	agentName            = "monitor"
	errorTime            = 3 * time.Minute
	warningTime          = 40 * time.Second
	stillRunningInterval = 25 * time.Second
)

var logger *logrus.Logger
var log *base.LogObject

type monitor struct {
	agentbase.AgentBase

	subscriptions       map[string]pubsub.Subscription
	pubDevicePortConfig pubsub.Publication
	clientConnected     chan bool
	serverNameAndPort   string
	// cache last known data structures to avoid sending duplicate messages
	lastNodeStatus *nodeStatus

	IPCServer *monitorIPCServer
}

func (ctx *monitor) readServerFile() error {
	var err error

	ctx.serverNameAndPort, err = types.Server()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Warn(err)
		return err
	}

	return nil
}

func (ctx *monitor) updateServerFile(newServer string) error {
	var remountErr error
	// 1. Find the CONFIG partition
	findCmd := exec.Command("/sbin/findfs", "PARTLABEL=CONFIG")
	deviceBytes, err := findCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to find CONFIG partition: %v -- output was: `%s'", err, string(deviceBytes))
	}
	devicePath := strings.TrimRight(string(deviceBytes), "\n\r")

	// 2. Create temp directory under /run
	tempDir, err := os.MkdirTemp("/run", "config-mount-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 3. Mount the CONFIG partition as read-write
	if err := syscall.Mount(devicePath,
		tempDir, "vfat", 0, "iocharset=iso8859-1"); err != nil {
		return fmt.Errorf("failed to mount CONFIG partition on device %v: %v", devicePath, err)
	}
	defer syscall.Unmount(tempDir, 0)

	// 4. Write new server file
	tempServerFile := filepath.Join(tempDir, filepath.Base(types.ServerFileName()))
	if err := os.WriteFile(tempServerFile, []byte(newServer), 0644); err != nil {
		return fmt.Errorf("failed to write new server file: %v", err)
	}

	// 5. Unmount temp directory (handled by defer)

	// 6. remount /config as rw. this is a tmpfs
	if err := syscall.Mount("none", "/config", "tmpfs",
		syscall.MS_REMOUNT, ""); err != nil {
		return fmt.Errorf("failed to remount /config RW: %v", err)
	}

	defer func() {
		// 7. remount /config as ro
		if err := syscall.Mount("none", "/config", "tmpfs",
			syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
			remountErr = fmt.Errorf("failed to remount /config RO: %v", err)
		}
	}()

	// 6. Update shadow copy in /config
	err = types.WriteServer(newServer)
	if err != nil {
		return err
	}

	if remountErr != nil {
		return remountErr
	}

	ctx.serverNameAndPort = newServer
	return nil
}

func newMonitorContext() *monitor {
	ctx := &monitor{
		subscriptions: make(map[string]pubsub.Subscription),
	}
	ctx.IPCServer = newIPCServer(ctx)
	ctx.clientConnected = ctx.IPCServer.c()
	ctx.lastNodeStatus = nil

	return ctx
}

// Run starts the monitor process and handles its lifecycle. It initializes the monitor context,
// sets up logging and IPC server, subscribes to necessary events, and begins event processing.
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int { //nolint:gocyclo
	logger = loggerArg
	log = logArg
	var err error

	ctx := newMonitorContext()

	agentbase.Init(ctx, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithWatchdog(ps, warningTime, errorTime),
		agentbase.WithArguments(arguments))

	if err = ctx.readServerFile(); err != nil {
		log.Fatalf("Server file exists but cannot be read `%v`", err)
	}

	if err = ctx.startIPCServer(); err != nil {
		log.Fatalf("Cannot start Monitor IPC server `%v`", err)
	}

	ctx.subscribe(ps)
	ctx.process(ps)
	return 0
}
