package types

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/sirupsen/logrus"
)

// AgentRunner is a function type that any agent that can be run by a caller process should export
type AgentRunner func(pubsubImpl *pubsub.PubSub, logger *logrus.Logger, baseLog *base.LogObject, arguments []string, baseDir string) int
