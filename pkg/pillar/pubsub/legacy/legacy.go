package legacy

import (
	"os"
	"sync"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
)

var onceLock = &sync.Mutex{}
var onceVal bool

// Protected by once()
var (
	log           *base.LogObject
	defaultPubsub *pubsub.PubSub
)

// once returns true the first time and then false
func once() bool {
	onceLock.Lock()
	defer onceLock.Unlock()
	if onceVal {
		return false
	} else {
		onceVal = true
		return true
	}
}

// Publish create a `Publication` for the given agent name and topic type.
// XXX remove? Used by ledmanagerutils.go
func Publish(agentName string, topicType interface{}) (pubsub.Publication, error) {
	if once() {
		log = base.NewSourceLogObject(agentName, os.Getpid())
		defaultPubsub = pubsub.New(&socketdriver.SocketDriver{Log: log}, log)
	}
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
	if once() {
		log = base.NewSourceLogObject(agentName, os.Getpid())
		defaultPubsub = pubsub.New(&socketdriver.SocketDriver{Log: log}, log)
	}
	log.Infof("legacy.PublishPersistent agentName(%s)", agentName)
	return defaultPubsub.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		TopicType:  topicType,
		Persistent: true,
	})
}
