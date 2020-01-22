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
	log.Infof("legacy.Publish agentName(%s)", agentName)
	return defaultPubsub.Publish(agentName, topicType)
}

// PublishPersistent create a `Publication` for the given agent name and topic
// type, but with persistence of the messages across reboots.
func PublishPersistent(agentName string, topicType interface{}) (pubsub.Publication, error) {
	log.Infof("legacy.PublishPersistent agentName(%s)", agentName)
	return defaultPubsub.PublishPersistent(agentName, topicType)
}

// PublishScope create a `Publication` for the given agent name and topic,
// restricted to a given scope.
func PublishScope(agentName string, agentScope string, topicType interface{}) (pubsub.Publication, error) {
	log.Infof("legacy.PublishScope agentName(%s), agentScope (%s)", agentName, agentScope)
	return defaultPubsub.PublishScope(agentName, agentScope, topicType)
}

// Subscribe create a subscription for the given agent name and topic
// optionally activating immediately. If `activate` is set to `false`
// (the default), then the subscription will not begin to send messages
// on the channel or process them until `Subscription.Start()` is called.
func Subscribe(agentName string, topicType interface{}, activate bool,
	ctx interface{}, options *pubsub.SubscriptionOptions) (pubsub.Subscription, error) {
	return defaultPubsub.Subscribe(agentName, topicType, activate, ctx, options)
}

// SubscribeScope create a subscription for the given agent name and topic,
// limited to a given scope,
// optionally activating immediately. If `activate` is set to `false`
// (the default), then the subscription will not begin to send messages
// on the channel or process them until `Subscription.Start()` is called.
func SubscribeScope(agentName string, agentScope string, topicType interface{},
	activate bool, ctx interface{}, options *pubsub.SubscriptionOptions) (pubsub.Subscription, error) {
	return defaultPubsub.SubscribeScope(agentName, agentScope, topicType, activate, ctx, options)
}

// SubscribePersistent create a subscription for the given agent name and topic,
// persistent,
// optionally activating immediately. If `activate` is set to `false`
// (the default), then the subscription will not begin to send messages
// on the channel or process them until `Subscription.Start()` is called.
func SubscribePersistent(agentName string, topicType interface{}, activate bool,
	ctx interface{}, options *pubsub.SubscriptionOptions) (pubsub.Subscription, error) {
	return defaultPubsub.SubscribePersistent(agentName, topicType, activate, ctx, options)
}
