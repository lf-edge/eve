// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"flag"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

const (
	agentName        = "evalmgr"
	errorTime        = 3 * time.Minute
	warningTime      = 40 * time.Second
	stillRunningTime = 25 * time.Second
)

// Version is set from Makefile
var Version = "No version specified"

var logger *logrus.Logger
var log *base.LogObject

type evalMgrContext struct {
	agentbase.AgentBase
	ps            *pubsub.PubSub
	pubEvalStatus pubsub.Publication

	// CLI flags can be added here if needed

	// Current state
	isEvaluationPlatform bool
	currentSlot          types.SlotName
	evalStatus           types.EvalStatus

	// Inventory collection status
	inventoryCollected bool
	inventoryDir       string

	// Timing and periodic updates
	statusUpdateTicker *time.Ticker
	rebootTicker       *time.Ticker
	rebootCountdown    int

	// Scheduler state
	schedulerState        SchedulerState
	stabilityTimer        *time.Timer
	scheduledRebootReason string
	stabilityStartTime    time.Time

	// Dependencies (for testing/mocking)
	partitionMgr PartitionManagerInterface
	systemReset  SystemResetInterface // System reboot operations (separate from partition management)
	agentLog     AgentLogInterface    // Agentlog abstraction for testing
	fs           afero.Fs             // Filesystem abstraction for testing
	testMode     bool                 // Skip filesystem operations like reboot logging in tests
	stopChan     chan struct{}        // For graceful shutdown in tests

	// Configurable timers (for testing - use defaults if not set)
	stabilityPeriod      time.Duration
	statusUpdateInterval time.Duration
	rebootTickInterval   time.Duration
	stillRunningInterval time.Duration
}

var debug = false

// newEvalMgrContext creates a new context with production defaults
func newEvalMgrContext(ps *pubsub.PubSub) *evalMgrContext {
	// Create production partition manager with real CGPT accessor
	cgptAccess := NewCgptAccess()
	agentLog := &RealAgentLog{}
	partitionMgr := NewPartitionManager(cgptAccess, agentLog)

	// Create production system reset handler (separate from partition management)
	systemReset := NewZbootSystemReset()

	return &evalMgrContext{
		ps:                   ps,
		partitionMgr:         partitionMgr,
		systemReset:          systemReset, // Production: use zboot directly for reboots
		agentLog:             agentLog,
		fs:                   afero.NewOsFs(),
		testMode:             false,
		stopChan:             make(chan struct{}, 1),
		stabilityPeriod:      StabilityPeriod,
		statusUpdateInterval: 25 * time.Second,
		rebootTickInterval:   time.Second,
		stillRunningInterval: 25 * time.Second,
	}
}

// Run is the main entry point for evalmgr, matching types.AgentRunner signature
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	logger = loggerArg
	log = logArg

	log.Noticef("Starting %s", agentName)

	// Initialize context with production defaults
	ctx := newEvalMgrContext(ps)
	agentbase.Init(ctx, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithWatchdog(ps, warningTime, errorTime),
		agentbase.WithArguments(arguments))

	// Access CLI flags - debug flag provided by agentbase
	debug = ctx.CLIParams().DebugOverride

	// Initialize publications
	if err := ctx.initPubSub(); err != nil {
		log.Fatal(err)
	}

	// Run the main loop
	if err := ctx.run(); err != nil {
		log.Errorf("evalmgr run failed: %v", err)
		return 1
	}

	log.Noticef("Exiting %s", agentName)
	return 0
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctx *evalMgrContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	// Debug flag is provided by agentbase automatically
	// Add custom flags here if needed
}

func (ctx *evalMgrContext) initPubSub() error {
	var err error

	// Initialize EvalStatus publication
	ctx.pubEvalStatus, err = ctx.ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			TopicType:  types.EvalStatus{},
			Persistent: false,
		})
	if err != nil {
		return fmt.Errorf("failed to create EvalStatus publication: %w", err)
	}

	return nil
}

func (ctx *evalMgrContext) run() error {
	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(ctx.stillRunningInterval)
	defer stillRunning.Stop()

	// Detect platform type early
	ctx.isEvaluationPlatform = utils.IsEvaluationPlatformFS(ctx.fs)
	log.Noticef("Platform detection: isEvaluationPlatform=%t", ctx.isEvaluationPlatform)

	if ctx.isEvaluationPlatform {
		// Evaluation platform: full initialization
		log.Noticef("Starting evaluation initialization")

		// Initialize and publish initial status
		if err := ctx.initializeEvaluation(); err != nil {
			return fmt.Errorf("failed to initialize evaluation: %w", err)
		}

		// Publish initial status (clean starting point for UI)
		// client.go executes wait.ForEvalStatus() and must be notified
		ctx.publishEvalStatus()

		// are we done already?
		if !ctx.evalStatus.IsOnboardingAllowed() {
			// Collect hardware inventory after initial status published
			log.Noticef("Collecting hardware inventory for partition %s", ctx.currentSlot)
			collector := NewInventoryCollector(log, ctx.fs)
			if err := collector.CollectInventory(string(ctx.currentSlot)); err != nil {
				log.Errorf("Failed to collect inventory: %v", err)
				// Continue execution even if inventory collection fails
			} else {
				log.Noticef("Successfully collected hardware inventory for %s", ctx.currentSlot)
				ctx.inventoryCollected = true
				ctx.inventoryDir = collector.GetInventoryDir(string(ctx.currentSlot))
				// Update and publish status with inventory info
				ctx.updateEvalStatus()
			}

			// Cleanup old inventories (keep last 30 days)
			if err := collector.CleanupOldInventories(30 * 24 * time.Hour); err != nil {
				log.Warnf("Failed to cleanup old inventories: %v", err)
			}

			// Initialize scheduler (Phase 3)
			if err := ctx.initializeScheduler(); err != nil {
				return fmt.Errorf("failed to initialize scheduler: %w", err)
			}

			// Setup periodic status updates
			ctx.statusUpdateTicker = time.NewTicker(ctx.statusUpdateInterval)
			defer ctx.statusUpdateTicker.Stop()

			// Setup reboot countdown ticker
			ctx.rebootTicker = time.NewTicker(ctx.rebootTickInterval)
			defer ctx.rebootTicker.Stop()
		}
	} else {
		// Non-evaluation platform: minimal setup
		log.Noticef("Non-evaluation platform - allowing onboarding, no evaluation needed")

		// Get current partition for status
		ctx.currentSlot = types.SlotName("unknown")
		if ctx.partitionMgr != nil {
			ctx.currentSlot = types.SlotName(ctx.partitionMgr.GetCurrentPartition())
		}

		// Create simple status allowing onboarding
		ctx.evalStatus = types.EvalStatus{
			IsEvaluationPlatform: false,
			CurrentSlot:          ctx.currentSlot,
			Phase:                types.EvalPhaseInit,
			AllowOnboard:         true,
			Note:                 "Normal platform, evaluation disabled",
			LastUpdated:          time.Now(),
		}

		// Publish status once
		ctx.publishEvalStatus()
	}

	// Start main event loop
	log.Noticef("Starting main event loop")
	for {
		select {
		case <-stillRunning.C:
			ctx.ps.StillRunning(agentName, warningTime, errorTime)

		case <-ctx.getStabilityTimerChannel():
			ctx.handleStabilityTimeout()

		case <-ctx.getStatusUpdateTickerChannel():
			ctx.handlePeriodicStatusUpdate()

		case <-ctx.getRebootTickerChannel():
			ctx.handleRebootCountdown()

		case <-ctx.stopChan:
			log.Noticef("Received stop signal, exiting run loop")
			return nil
		}
	}
}

func (ctx *evalMgrContext) handlePeriodicStatusUpdate() {
	log.Functionf("handlePeriodicStatusUpdate")

	// Update and publish current status with timing info
	ctx.updateTimingFields()
	ctx.publishEvalStatus()
}

func (ctx *evalMgrContext) handleRebootCountdown() {
	// Update reboot countdown if we're in reboot phase
	if ctx.rebootCountdown > 0 {
		ctx.rebootCountdown--
		if ctx.rebootCountdown <= 0 {
			log.Noticef("Reboot countdown expired, executing reboot")
			if err := ctx.executeReboot(); err != nil {
				log.Errorf("Failed to execute reboot: %v", err)
				// Reset countdown for retry in case of failure
				ctx.rebootCountdown = 10
			}
			// Note: In test mode, mock partition manager's Reset() will send stop signal
			// to simulate system reboot. In production, system reboots and we never return.
		} else {
			// Update status immediately during countdown to show progress
			ctx.updateTimingFields()
			ctx.publishEvalStatus()
		}
	}
}

func (ctx *evalMgrContext) updateTimingFields() {
	// Update timing fields based on current state
	if ctx.evalStatus.Phase == types.EvalPhaseTesting && !ctx.evalStatus.TestStartTime.IsZero() {
		// Keep existing timing - already set when evaluation started
	} else if ctx.evalStatus.Phase == types.EvalPhaseTesting && ctx.evalStatus.TestStartTime.IsZero() {
		// Start timing if we just entered evaluation phase
		ctx.evalStatus.TestStartTime = time.Now()
		ctx.evalStatus.TestDuration = StabilityPeriod
	}

	// Update reboot countdown in status
	ctx.evalStatus.RebootCountdown = ctx.rebootCountdown
	ctx.evalStatus.LastUpdated = time.Now()
}

// getStabilityTimerChannel returns the stability timer channel or nil if no timer
func (ctx *evalMgrContext) getStabilityTimerChannel() <-chan time.Time {
	if ctx.stabilityTimer == nil {
		return nil
	}
	return ctx.stabilityTimer.C
}

func (ctx *evalMgrContext) getStatusUpdateTickerChannel() <-chan time.Time {
	if ctx.statusUpdateTicker == nil {
		return nil
	}
	return ctx.statusUpdateTicker.C
}

func (ctx *evalMgrContext) getRebootTickerChannel() <-chan time.Time {
	if ctx.rebootTicker == nil {
		return nil
	}
	return ctx.rebootTicker.C
}
