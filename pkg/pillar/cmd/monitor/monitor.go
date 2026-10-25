// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/types/monitorapi"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
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

	// latest of each input feeding the aggregated DeviceStatus snapshot
	lastOnboarding   types.OnboardingStatus
	lastEdgeNodeInfo types.EdgeNodeInfo
	lastZedAgent     types.ZedAgentStatus
	lastVault        types.VaultStatus
	// lastDeviceStatus dedups the assembled snapshot
	lastDeviceStatus *monitorapi.DeviceStatus
	// lastDPCList is the device's current port config, used as the base the
	// write path (SetInterfaceConfig) patches.
	lastDPCList *types.DevicePortConfigList

	IPCServer *monitorIPCServer
}

func (ctx *monitor) readServerFile() error {
	if _, err := os.Stat(types.ServerFileName); errors.Is(err, fs.ErrNotExist) {
		// server file does not exist. This is not an error but a possible case
		ctx.serverNameAndPort = ""
		return nil
	}
	server, err := os.ReadFile(types.ServerFileName)
	if err != nil {
		log.Fatal(err)
		return err
	}
	ctx.serverNameAndPort = strings.TrimSpace(string(server))
	return nil
}

func (ctx *monitor) updateServerFile(newServer string) error {
	var remountErr error
	// 1. Write the new server file to the CONFIG partition on the boot disk
	if err := zboot.WithConfigPartitionRW(func(mountDir string) error {
		serverFile := filepath.Join(mountDir, filepath.Base(types.ServerFileName))
		return os.WriteFile(serverFile, []byte(newServer), 0644)
	}); err != nil {
		return fmt.Errorf("failed to write new server file to CONFIG partition: %v", err)
	}

	// 2. remount /config as rw. this is a tmpfs
	if err := syscall.Mount("none", "/config", "tmpfs",
		syscall.MS_REMOUNT, ""); err != nil {
		return fmt.Errorf("failed to remount /config RW: %v", err)
	}

	defer func() {
		// 4. remount /config as ro
		if err := syscall.Mount("none", "/config", "tmpfs",
			syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
			remountErr = fmt.Errorf("failed to remount /config RO: %v", err)
		}
	}()

	// 3. Update shadow copy in /config
	if err := os.WriteFile(types.ServerFileName, []byte(newServer), 0644); err != nil {
		return fmt.Errorf("failed to update shadow copy: %v", err)
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
	ctx.lastDeviceStatus = nil

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
