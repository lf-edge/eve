// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"flag"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

//UCPhase tells us which phase we are in
type UCPhase uint32

//Different UCPhase phases we support
const (
	UCPhasePreVault UCPhase = iota + 0
	UCPhasePostVault
)

//preVaultconversionHandlers run before vault is ready
//Any handler that interacts with types.SealedDirName
//should be in postVaultconversionHandlers
var preVaultconversionHandlers = []ConversionHandler{
	{
		description: "Convert Global Settings to new format",
		handlerFunc: convertGlobalConfig,
	},
	{
		description: "Move ConfigItemValueMap from /persist/config to /persist/status",
		handlerFunc: moveConfigItemValueMap,
	},
	{
		description: "Apply defaults for new items in ConfigItemValueMap",
		handlerFunc: applyDefaultConfigItem,
	},
}

//postVaultconversionHandlers run after vault is setup
//Any handler that is not related to types.SealedDirName
//should be in preVaultconversionHandlers
var postVaultconversionHandlers = []ConversionHandler{
	{
		description: "Move volumes to /persist/vault",
		handlerFunc: convertPersistVolumes,
	},
	{
		description: "Move verified files to /persist/vault/verifier/verified",
		handlerFunc: renameVerifiedFiles,
	},
}

type ucContext struct {
	agentName     string
	debugOverride bool
	noFlag        bool

	// FilePaths. These are defined here instead of consts for easier unit tests
	persistDir       string
	persistConfigDir string
	persistStatusDir string
	ps               *pubsub.PubSub
}

func (ctx ucContext) oldConfigItemValueMapDir() string {
	return ctx.persistConfigDir + "/ConfigItemValueMap/"
}
func (ctx ucContext) oldConfigItemValueMapFile() string {
	return ctx.oldConfigItemValueMapDir() + "/global.json"
}
func (ctx ucContext) globalConfigDir() string {
	return ctx.persistConfigDir + "/GlobalConfig"
}
func (ctx ucContext) globalConfigFile() string {
	return ctx.globalConfigDir() + "/global.json"
}
func (ctx ucContext) newConfigItemValueMapDir() string {
	return ctx.persistStatusDir + "/zedagent/ConfigItemValueMap/"
}
func (ctx ucContext) newConfigItemValueMapFile() string {
	return ctx.newConfigItemValueMapDir() + "/global.json"
}

// Old location for volumes
func (ctx ucContext) imgDir() string {
	return ctx.persistDir + "/img/"
}

// Old location for volumes
func (ctx ucContext) preparedDir() string {
	return ctx.persistDir + "/runx/pods/prepared/"
}

// New location for volumes
func (ctx ucContext) volumesDir() string {
	return ctx.persistDir + "/vault/volumes/"
}

// checkpoint file for EdgeDevConfig
func (ctx ucContext) configCheckpointFile() string {
	return ctx.persistDir + "/checkpoint/lastconfig"
}

func runHandlers(ctxPtr *ucContext, handlers []ConversionHandler) {
	for _, handler := range handlers {
		log.Functionf("upgradeconverter.Run: Running Conversion handler: %s",
			handler.description)
		err := handler.handlerFunc(ctxPtr)
		if err != nil {
			log.Errorf("upgradeconverter.Run: Handler %s failed. err %s\n ctx:%+v",
				handler.description, err, *ctxPtr)
		}
	}
}

var logger *logrus.Logger
var log *base.LogObject

// Run - runs the main upgradeconverter process
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject) int {
	logger = loggerArg
	log = logArg
	ctx := &ucContext{agentName: "upgradeconverter",
		persistDir:       types.PersistDir,
		persistConfigDir: types.PersistConfigDir,
		persistStatusDir: types.PersistStatusDir,
		ps:               ps,
	}
	debugPtr := flag.Bool("d", false, "Debug flag")
	persistPtr := flag.String("p", "/persist", "persist directory")
	noFlagPtr := flag.Bool("n", false, "Don't do anything just log flag")
	flag.Parse()
	ctx.debugOverride = *debugPtr
	ctx.persistDir = *persistPtr // XXX remove? Or use for tests?
	ctx.noFlag = *noFlagPtr
	if ctx.debugOverride {
		logger.SetLevel(logrus.TraceLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	if err := pidfile.CheckAndCreatePidfile(log, ctx.agentName); err != nil {
		log.Fatal(err)
	}
	log.Functionf("Starting %s\n", ctx.agentName)

	phase := UCPhasePreVault
	if len(flag.Args()) != 0 {
		switch flag.Args()[0] {
		case "pre-vault":
			phase = UCPhasePreVault
		case "post-vault":
			phase = UCPhasePostVault
		default:
			log.Errorf("Unknown argument %s, running pre-vault phase", flag.Args()[0])
		}
	}
	runPhase(ctx, phase)
	return 0
}

// HandlerFunc - defines functions to handle each conversion
type HandlerFunc func(ctx *ucContext) error

// ConversionHandler - defines type for processing
type ConversionHandler struct {
	description string
	handlerFunc HandlerFunc
}

//RunPostVaultHandlers invokes postVaultconversionHandlers
//and notifies the caller through the provided ucChan channel
//the channel is useful for calling from other agent modules
//without missing watchdog, by spawning this as a task, and
//select()ing for its completion
func RunPostVaultHandlers(moduleName string,
	ps *pubsub.PubSub,
	loggerArg *logrus.Logger,
	logArg *base.LogObject,
	debugOverride bool, ucChan chan struct{}) {
	logger = loggerArg
	log = logArg
	ctx := &ucContext{agentName: moduleName,
		persistDir:       types.PersistDir,
		persistConfigDir: types.PersistConfigDir,
		persistStatusDir: types.PersistStatusDir,
		ps:               ps,
	}
	runPhase(ctx, UCPhasePostVault)
	log.Notice("RunPostVaultHandlers completed, notifying caller")
	ucChan <- struct{}{}
}

//RunPreVaultHandlers invokes preVaultconversionHandlers
//and notifies the caller through the provided ucChan channel
//the channel is useful for calling from other agent modules
//without missing watchdog, by spawning this as a task, and
//select()ing for its completion
func RunPreVaultHandlers(moduleName string,
	ps *pubsub.PubSub,
	loggerArg *logrus.Logger,
	logArg *base.LogObject,
	debugOverride bool, ucChan chan struct{}) {
	logger = loggerArg
	log = logArg
	ctx := &ucContext{agentName: moduleName,
		persistDir:       types.PersistDir,
		persistConfigDir: types.PersistConfigDir,
		persistStatusDir: types.PersistStatusDir,
		ps:               ps,
	}
	runPhase(ctx, UCPhasePreVault)
	log.Notice("RunPreVaultHandlers completed, notifying caller")
	ucChan <- struct{}{}
}

//helper to invoke handlers according to the phase supplied
func runPhase(ctx *ucContext, phase UCPhase) {
	switch phase {
	case UCPhasePreVault:
		runHandlers(ctx, preVaultconversionHandlers)
	case UCPhasePostVault:
		runHandlers(ctx, postVaultconversionHandlers)
	default:
		log.Errorf("Unknown phase %d, ignoring", phase)
	}
}
