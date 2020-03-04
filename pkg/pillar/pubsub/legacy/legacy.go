package legacy

import (
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	log "github.com/sirupsen/logrus"
)

var (
	defaultPubsub = pubsub.New(&socketdriver.SocketDriver{})
)

// Publish create a `Publication` for the given agent name and topic type.
func Publish(agentName string, topicType interface{}) (pubsub.Publication, error) {
	log.Debugf("legacy.Publish agentName(%s)", agentName)
	return defaultPubsub.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: topicType,
	})
}

// PublishPersistent create a `Publication` for the given agent name and topic
// type, but with persistence of the messages across reboots.
func PublishPersistent(agentName string, topicType interface{}) (pubsub.Publication, error) {
	log.Infof("legacy.PublishPersistent agentName(%s)", agentName)
	return defaultPubsub.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		TopicType:  topicType,
		Persistent: true,
	})
}

// PublishScope create a `Publication` for the given agent name and topic,
// restricted to a given scope.
func PublishScope(agentName string, agentScope string, topicType interface{}) (pubsub.Publication, error) {
	log.Infof("legacy.PublishScope agentName(%s), agentScope (%s)", agentName, agentScope)
	return defaultPubsub.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		TopicType:  topicType,
		AgentScope: agentScope,
	})
}

// Subscribe create a subscription for the given agent name and topic
// optionally activating immediately. If `activate` is set to `false`
// (the default), then the subscription will not begin to send messages
// on the channel or process them until `Subscription.Start()` is called.
func Subscribe(agentName string, topicType interface{}, activate bool,
	ctx interface{}, options *pubsub.SubscriptionOptions) (pubsub.Subscription, error) {

	if options == nil {
		options = &pubsub.SubscriptionOptions{}
	}
	return defaultPubsub.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler:  options.CreateHandler,
		ModifyHandler:  options.ModifyHandler,
		DeleteHandler:  options.DeleteHandler,
		RestartHandler: options.RestartHandler,
		SyncHandler:    options.SyncHandler,
		WarningTime:    options.WarningTime,
		ErrorTime:      options.ErrorTime,
		AgentName:      agentName,
		TopicImpl:      topicType,
		Activate:       activate,
		Ctx:            ctx,
		Persistent:     false,
	})
}

// SubscribeScope create a subscription for the given agent name and topic,
// limited to a given scope,
// optionally activating immediately. If `activate` is set to `false`
// (the default), then the subscription will not begin to send messages
// on the channel or process them until `Subscription.Start()` is called.
func SubscribeScope(agentName string, agentScope string, topicType interface{},
	activate bool, ctx interface{}, options *pubsub.SubscriptionOptions) (pubsub.Subscription, error) {
	if options == nil {
		options = &pubsub.SubscriptionOptions{}
	}
	return defaultPubsub.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler:  options.CreateHandler,
		ModifyHandler:  options.ModifyHandler,
		DeleteHandler:  options.DeleteHandler,
		RestartHandler: options.RestartHandler,
		SyncHandler:    options.SyncHandler,
		WarningTime:    options.WarningTime,
		ErrorTime:      options.ErrorTime,
		AgentName:      agentName,
		AgentScope:     agentScope,
		TopicImpl:      topicType,
		Activate:       activate,
		Ctx:            ctx,
		Persistent:     false,
	})
}

// SubscribePersistent create a subscription for the given agent name and topic,
// persistent,
// optionally activating immediately. If `activate` is set to `false`
// (the default), then the subscription will not begin to send messages
// on the channel or process them until `Subscription.Start()` is called.
func SubscribePersistent(agentName string, topicType interface{}, activate bool,
	ctx interface{}, options *pubsub.SubscriptionOptions) (pubsub.Subscription, error) {
	if options == nil {
		options = &pubsub.SubscriptionOptions{}
	}
	return defaultPubsub.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler:  options.CreateHandler,
		ModifyHandler:  options.ModifyHandler,
		DeleteHandler:  options.DeleteHandler,
		RestartHandler: options.RestartHandler,
		SyncHandler:    options.SyncHandler,
		WarningTime:    options.WarningTime,
		ErrorTime:      options.ErrorTime,
		AgentName:      agentName,
		TopicImpl:      topicType,
		Activate:       activate,
		Ctx:            ctx,
		Persistent:     true,
	})
}
