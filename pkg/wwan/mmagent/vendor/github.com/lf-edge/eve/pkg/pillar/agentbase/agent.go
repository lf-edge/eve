package agentbase

import (
	"flag"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"

	"github.com/sirupsen/logrus"
)

// Agent - Interface for all agents.
// Each agent is expected to have an AgentState that implements
// this interface.
type Agent interface {
	GetAgentBase() *AgentBase
	AddAgentSpecificCLIFlags(*flag.FlagSet)
	ProcessAgentSpecificCLIFlags(*flag.FlagSet)
}

// CliParams - stores all the common cli params
type CliParams struct {
	DebugOverride bool
}

// AgentBase - a struct that represents a general agent context
type AgentBase struct {
	pubSub       *pubsub.PubSub
	logger       *logrus.Logger
	log          *base.LogObject
	cliParams    CliParams
	errorTime    time.Duration
	warningTime  time.Duration
	agentName    string
	needWatchdog bool
	needPidFile  bool
	arguments    []string
	baseDir      string
}

// AgentOpt function may be used to modify options
type AgentOpt func(*AgentBase)

// WithPidFile creates pid file
func WithPidFile() AgentOpt {
	return func(a *AgentBase) {
		a.needPidFile = true
	}
}

// WithArguments defines arguments
func WithArguments(arguments []string) AgentOpt {
	return func(a *AgentBase) {
		a.arguments = arguments
	}
}

// WithWatchdog defines options required to initialize watchdog
func WithWatchdog(pubSub *pubsub.PubSub, warningTime, errorTime time.Duration) AgentOpt {
	return func(a *AgentBase) {
		a.pubSub = pubSub
		a.warningTime = warningTime
		a.errorTime = errorTime
		a.needWatchdog = true
	}
}

// WithBaseDir defines base directory for file-related activities, such as pidfile
func WithBaseDir(baseDir string) AgentOpt {
	return func(a *AgentBase) {
		a.baseDir = baseDir
	}
}

// CLIParams returns CliParams
func (a *AgentBase) CLIParams() CliParams {
	return a.cliParams
}

// Logger returns Logger
func (a *AgentBase) Logger() *logrus.Logger {
	return a.logger
}

// GetAgentBase returns AgentBase implementation
func (a *AgentBase) GetAgentBase() *AgentBase {
	return a
}

// AddAgentSpecificCLIFlags adds CLI options
func (a *AgentBase) AddAgentSpecificCLIFlags(_ *flag.FlagSet) {}

// ProcessAgentSpecificCLIFlags process received CLI options
func (a *AgentBase) ProcessAgentSpecificCLIFlags(_ *flag.FlagSet) {}

// processCLIFlags - Add flags common to all agents
func processCLIFlags(agentBase Agent) error {
	ctx := agentBase.GetAgentBase()
	flagSet := flag.NewFlagSet(ctx.agentName, flag.ExitOnError)
	debugPtr := flagSet.Bool("d", false, "Debug flag")
	agentBase.AddAgentSpecificCLIFlags(flagSet)
	if err := flagSet.Parse(ctx.arguments); err != nil {
		return err
	}
	ctx.cliParams.DebugOverride = *debugPtr
	agentBase.ProcessAgentSpecificCLIFlags(flagSet)
	return nil
}

// Init - a general init function that will handle the common code for agents
func Init(agent Agent, logger *logrus.Logger, log *base.LogObject, agentName string, opts ...AgentOpt) {
	agentBase := agent.GetAgentBase()
	for _, opt := range opts {
		opt(agentBase)
	}
	agentBase.logger = logger
	agentBase.log = log
	agentBase.agentName = agentName
	if err := processCLIFlags(agent); err != nil {
		log.Fatal(err)
	}
	debugOverride := agentBase.cliParams.DebugOverride
	if debugOverride {
		logger.SetLevel(logrus.TraceLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	if agentBase.needPidFile {
		if err := pidfile.CheckAndCreatePidfile(log, agentBase.agentName, pidfile.WithBaseDir(agentBase.baseDir)); err != nil {
			log.Fatal(err)
		}
	}
	log.Functionf("Starting %s\n", agentBase.agentName)
	if agentBase.needWatchdog {
		agentBase.pubSub.StillRunning(agentBase.agentName,
			agentBase.warningTime,
			agentBase.errorTime)
	}
}
