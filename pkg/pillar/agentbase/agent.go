package agentbase

import (
	"flag"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"

	log "github.com/sirupsen/logrus"
)

// AgentBase - Interface for all agents to use the AgentBase.
// Each agent is expected to have a Context that implements
// this interface.
type AgentBase interface {
	// AgentBaseContext - returns a pointer to the agentbase context
	AgentBaseContext() *Context
}

const (
	// DefaultErrorTime - the default error time
	DefaultErrorTime = 3 * time.Minute
	// DefaultWarningTime - the default warning time
	DefaultWarningTime = 40 * time.Second
	defaultLogLevel    = log.InfoLevel
)

// DefaultContext - returns a context with default values
func DefaultContext(agentName string) Context {
	return Context{
		AgentName:   agentName,
		WarningTime: DefaultWarningTime,
		ErrorTime:   DefaultErrorTime,
		AgentOptions: AgentOptions{
			CheckAndCreatePidFile: true,
			StartAgentLog:         true,
			// SubscribeToGlobalConfig - Once all the agents are converted and tested this will be changed to
			// true and the explicit places where this is set to true will removed.
			SubscribeToGlobalConfig: false,
			GlobalConfigSubscriptionOptions: pubsub.SubscriptionOptions{
				AgentName:   "",
				TopicImpl:   types.ConfigItemValueMap{},
				Activate:    false,
				WarningTime: DefaultWarningTime,
				ErrorTime:   DefaultErrorTime,
			},
		},
		GlobalConfig: types.DefaultConfigItemValueMap(),
	}
}

// CliParams - stores all the common cli params
type CliParams struct {
	DebugOverride bool
	Debug         bool
}

// AgentOptions - stores various options an agent may use to control different functions in Run()
type AgentOptions struct {
	CheckAndCreatePidFile           bool
	AddAgentCLIFlagsFnPtr           ContextCallbackFnType
	ProcessAgentCLIFlagsFnPtr       ContextCallbackFnType
	StartAgentLog                   bool
	SubscribeToGlobalConfig         bool
	GlobalConfigSubscriptionOptions pubsub.SubscriptionOptions
}

// ContextCallbackFnType - Defines a structure for the type of function we use to add and process cli flags
type ContextCallbackFnType func()

// GlobalConfigCallbackFn - Defines a structure for the type of function we use to modify global config items
type GlobalConfigCallbackFn func(gcp *types.ConfigItemValueMap)

// Context - a struct that represents a general agent context
type Context struct {
	CLIParams    CliParams
	ErrorTime    time.Duration
	WarningTime  time.Duration
	AgentName    string
	AgentOptions AgentOptions

	SubGlobalConfig     pubsub.Subscription
	GlobalConfig        *types.ConfigItemValueMap
	GCInitialized       bool
	GlobalConfigHandler GlobalConfigCallbackFn
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
func Run(ps *pubsub.PubSub, ctx AgentBase) {
	agentBase := ctx.(AgentBase)
	processCLIFlags(agentBase)
	agentBaseContext := agentBase.AgentBaseContext()
	if agentBaseContext.CLIParams.DebugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(defaultLogLevel)
	}
	if agentBaseContext.AgentOptions.StartAgentLog {
		agentlog.Init(agentBaseContext.AgentName)
	}
	if agentBaseContext.AgentOptions.CheckAndCreatePidFile {
		if err := pidfile.CheckAndCreatePidfile(agentBaseContext.AgentName); err != nil {
			log.Fatal(err)
		}
	}
	log.Infof("Starting %s\n", agentBaseContext.AgentName)

	if agentBaseContext.AgentOptions.SubscribeToGlobalConfig {
		globalConfigSub, err := SubscribeToGlobalConfig(ps, ctx)
		globalConfigSub.Activate()
		if err != nil {
			log.Fatal(err)
		}
	}
}
