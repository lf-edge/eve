package legacy

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
)

var (
	basename      = "legacy-unknown-agent"
	log           = base.NewSourceLogObject(basename, 0)
	defaultPubsub = pubsub.New(&socketdriver.SocketDriver{Log: log}, log)
)

// Publish create a `Publication` for the given agent name and topic type.
// XXX remove? Used by ledmanagerutils.go
func Publish(agentName string, topicType interface{}) (pubsub.Publication, error) {
	log.Debugf("legacy.Publish agentName(%s)", agentName)
	return defaultPubsub.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: topicType,
	})
}

// PublishPersistent create a `Publication` for the given agent name and topic
// type, but with persistence of the messages across reboots.
// XXX remove? Used by globalutils.go
func PublishPersistent(agentName string, topicType interface{}) (pubsub.Publication, error) {
	log.Infof("legacy.PublishPersistent agentName(%s)", agentName)
	return defaultPubsub.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		TopicType:  topicType,
		Persistent: true,
	})
}
