// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"github.com/lf-edge/eve/pkg/pillar/agentbase"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

var conversionHandlers = []ConversionHandler{
	{
		description: "Convert Global Settings to new format",
		handlerFunc: convertGlobalConfig,
	},
}

type ucContext struct {
	agentBaseContext agentbase.Context
	// FilePaths. These are defined here instead of consts for easier unit tests
	persistConfigDir string
	varTmpDir        string
}

func (ctx ucContext) configItemValueMapDir() string {
	return ctx.persistConfigDir + "/ConfigItemValueMap/"
}
func (ctx ucContext) configItemValueMapFile() string {
	return ctx.configItemValueMapDir() + "/global.json"
}
func (ctx ucContext) globalConfigDir() string {
	return ctx.persistConfigDir + "/GlobalConfig"
}
func (ctx ucContext) globalConfigFile() string {
	return ctx.globalConfigDir() + "/global.json"
}

func runHandlers(ctxPtr *ucContext) {
	for _, handler := range conversionHandlers {
		log.Printf("upgradeconverter.Run: Running Conversion handler: %s",
			handler.description)
		err := handler.handlerFunc(ctxPtr)
		if err != nil {
			log.Errorf("upgradeconverter.Run: Handler %s failed. err %s\n ctx:%+v",
				handler.description, err, *ctxPtr)
		}
	}
}
func newUcContext() *ucContext {
	ctx := ucContext{
		persistConfigDir: types.PersistConfigDir,
		varTmpDir:        "/var/tmp",
	}

	ctx.agentBaseContext = agentbase.DefaultContext("upgradeconverter")
	ctx.agentBaseContext.NeedWatchdog = false
	ctx.agentBaseContext.CheckAndCreatePidFile = true

	return &ctx
}

func (ctx *ucContext) AgentBaseContext() *agentbase.Context {
	return &ctx.agentBaseContext
}

// Run - runs the main upgradeconverter process
func Run(ps *pubsub.PubSub) {
	ctxPtr := newUcContext()

	agentbase.Run(ctxPtr)

	runHandlers(ctxPtr)
}

// HandlerFunc - defines functions to handle each conversion
type HandlerFunc func(ctx *ucContext) error

// ConversionHandler - defines type for processing
type ConversionHandler struct {
	description string
	handlerFunc HandlerFunc
}
