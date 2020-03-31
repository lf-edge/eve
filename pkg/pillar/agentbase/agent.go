package agentbase

import (
	"flag"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"time"

	log "github.com/sirupsen/logrus"
)

// AgentBase - Interface for all agents to use the AgentBase.
// Each agent is expected to have a Context that implements
// this interface.
type AgentBase interface {
	AgentBaseContext() *Context
}

const (
	defaultErrorTime   = 3 * time.Minute
	defaultWarningTime = 40 * time.Second
)

// DefaultContext - returns a context with default values
func DefaultContext(agentName string) Context {
	return Context{
		AgentName:             agentName,
		WarningTime:           defaultWarningTime,
		ErrorTime:             defaultErrorTime,
		NeedWatchdog:          true,
		CheckAndCreatePidFile: true,
		InitializeAgent:       true,
	}
}

// CliParams - stores all the common cli params
type CliParams struct {
	DebugOverride bool
	Debug         bool
}

// ContextCallbackFnType - Defines a structure for the type of function we use to add and process cli flags
type ContextCallbackFnType func()

// Context - a struct that represents a general agent context
type Context struct {
	CLIParams                 CliParams
	ErrorTime                 time.Duration
	WarningTime               time.Duration
	AgentName                 string
	NeedWatchdog              bool
	CheckAndCreatePidFile     bool
	AddAgentCLIFlagsFnPtr     ContextCallbackFnType
	ProcessAgentCLIFlagsFnPtr ContextCallbackFnType
	InitializeAgent           bool
}

// processCLIFlags - Add flags common to all agents
func processCLIFlags(agentBase AgentBase) {
	ctx := agentBase.AgentBaseContext()
	flag.BoolVar(&ctx.CLIParams.Debug, "d", false, "Debug flag")
	if ctx.AddAgentCLIFlagsFnPtr != nil {
		ctx.AddAgentCLIFlagsFnPtr()
	}
	flag.Parse()
	if ctx.ProcessAgentCLIFlagsFnPtr != nil {
		ctx.ProcessAgentCLIFlagsFnPtr()
	}
	ctx.CLIParams.DebugOverride = ctx.CLIParams.Debug
}

// Run - a general run function that will handle all of the common code for agents
func Run(agentSpecificContext AgentBase) {
	processCLIFlags(agentSpecificContext)
	ctx := agentSpecificContext.AgentBaseContext()
	if ctx.CLIParams.DebugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	if ctx.InitializeAgent {
		agentlog.Init(ctx.AgentName)
	}
	if ctx.CheckAndCreatePidFile {
		if err := pidfile.CheckAndCreatePidfile(ctx.AgentName); err != nil {
			log.Fatal(err)
		}
	}
	log.Infof("Starting %s\n", ctx.AgentName)
	if ctx.NeedWatchdog {
		agentlog.StillRunning(ctx.AgentName, ctx.WarningTime, ctx.ErrorTime)
	}
}
