package agentbase

import (
	"flag"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
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
	DefaultErrorTime   = 3 * time.Minute
	DefaultWarningTime = 40 * time.Second
)

// DefaultContext - returns a context with default values
func DefaultContext(agentName string) Context {
	return Context{
		AgentName:   agentName,
		WarningTime: DefaultWarningTime,
		ErrorTime:   DefaultErrorTime,
		AgentOptions: AgentOptions{
			NeedWatchdog:          true,
			CheckAndCreatePidFile: true,
			InitializeAgent:       true,
			CreateGlobalConfigSub: true,
		},
	}
}

// CliParams - stores all the common cli params
type CliParams struct {
	DebugOverride bool
	Debug         bool
}
type AgentOptions struct {
	NeedWatchdog              bool
	CheckAndCreatePidFile     bool
	AddAgentCLIFlagsFnPtr     ContextCallbackFnType
	ProcessAgentCLIFlagsFnPtr ContextCallbackFnType
	InitializeAgent           bool
	CreateGlobalConfigSub     bool
}

// ContextCallbackFnType - Defines a structure for the type of function we use to add and process cli flags
type ContextCallbackFnType func()

// Context - a struct that represents a general agent context
type Context struct {
	CLIParams    CliParams
	ErrorTime    time.Duration
	WarningTime  time.Duration
	AgentName    string
	AgentOptions AgentOptions

	StillRunning *time.Ticker

	subGlobalConfig pubsub.Subscription
	globalConfig    *types.ConfigItemValueMap
	GCInitialized   bool
}

// processCLIFlags - Add flags common to all agents
func processCLIFlags(agentBase AgentBase) {
	ctx := agentBase.AgentBaseContext()
	flag.BoolVar(&ctx.CLIParams.Debug, "d", false, "Debug flag")
	if ctx.AgentOptions.AddAgentCLIFlagsFnPtr != nil {
		ctx.AgentOptions.AddAgentCLIFlagsFnPtr()
	}
	flag.Parse()
	if ctx.AgentOptions.ProcessAgentCLIFlagsFnPtr != nil {
		ctx.AgentOptions.ProcessAgentCLIFlagsFnPtr()
	}
	ctx.CLIParams.DebugOverride = ctx.CLIParams.Debug
}

// Run - a general run function that will handle all of the common code for agents
func Run(ps *pubsub.PubSub, ctx interface{}) {
	agentBase := ctx.(AgentBase)
	processCLIFlags(agentBase)
	agentBaseContext := agentBase.AgentBaseContext()
	if agentBaseContext.CLIParams.DebugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	if agentBaseContext.AgentOptions.InitializeAgent {
		agentlog.Init(agentBaseContext.AgentName)
	}
	if agentBaseContext.AgentOptions.CheckAndCreatePidFile {
		if err := pidfile.CheckAndCreatePidfile(agentBaseContext.AgentName); err != nil {
			log.Fatal(err)
		}
	}
	log.Infof("Starting %s\n", agentBaseContext.AgentName)
	if agentBaseContext.AgentOptions.NeedWatchdog {
		agentlog.StillRunning(agentBaseContext.AgentName, agentBaseContext.WarningTime, agentBaseContext.ErrorTime)
	}

	agentBaseContext.StillRunning = time.NewTicker(25 * time.Second)

	if agentBaseContext.AgentOptions.CreateGlobalConfigSub {
		globalConfigSub, err := NewGlobalConfigSub(ps, ctx)
		globalConfigSub.Activate()
		if err != nil {
			log.Fatal(err)
		}
	}
}
