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
	AddAgentSpecificCLIFlags()
	ProcessAgentSpecificCLIFlags()
}

// CliParams - stores all the common cli params
type CliParams struct {
	DebugOverride bool
}

// Context - a struct that represents a general agent context
type Context struct {
	CLIParams    CliParams
	ErrorTime    time.Duration
	WarningTime  time.Duration
	AgentName    string
	NeedWatchdog bool
}

// processCLIFlags - Add flags common to all agents
func processCLIFlags(agentBase AgentBase) {
	debugPtr := flag.Bool("d", false, "Debug flag")
	agentBase.AddAgentSpecificCLIFlags()
	flag.Parse()
	ctx := agentBase.AgentBaseContext()
	ctx.CLIParams.DebugOverride = *debugPtr
	agentBase.ProcessAgentSpecificCLIFlags()
}

// Run - a general run function that will handle all of the common code for agents
func Run(agentSpecificContext AgentBase) {
	processCLIFlags(agentSpecificContext)
	ctx := agentSpecificContext.AgentBaseContext()
	debugOverride := ctx.CLIParams.DebugOverride
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	agentlog.Init(ctx.AgentName)
	if err := pidfile.CheckAndCreatePidfile(ctx.AgentName); err != nil {
		log.Fatal(err)
	}
	log.Infof("Starting %s\n", ctx.AgentName)
	if ctx.NeedWatchdog {
		agentlog.StillRunning(ctx.AgentName, ctx.WarningTime, ctx.ErrorTime)
	}
}
