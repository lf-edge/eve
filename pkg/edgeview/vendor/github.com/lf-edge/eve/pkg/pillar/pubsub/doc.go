// Package pubsub provides access to publish/subscribe semantics and engine
// in a single host context across processes. The actual implementation of
// the publishing and subscribing are provided by an engine passed to `pubsub`.
//
// This documentation covers:
//
// * how to use pubsub in another module
// * how to implement a driver.
//
// # Usage
//
// To use pubsub, you must first instantiate a pubsub instance, passing it a
// driver, and then use the instance. In general, there will be one pubsub
// instance per process, but that is not strictly necessary.
//
// Once instantiated, you can retrieve a publisher or a subscriber from the
// `pubsub.PubSub`.
//
// To instantiate pubsub:
//
//	import "github.com/lf-edge/eve/pkg/pillar/pubsub"
//	ps := pubsub.New(driver)
//
// where `driver` is a `struct` that implements `pubsub.Driver`.
//
// Included is the `SocketDriver`, which uses a Unix-domain socket to
// communicate between publishers and subscribers, and local directories to
// store persistent messages.
//
// see the documentation for each element to understand its usage.
//
// For example:
//
//	import (
//	  "github.com/lf-edge/eve/pkg/pillar/pubsub"
//	  "github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
//	)
//
//	func foo() {
//	  driver := socketdriver.SocketDriver{}
//	  ps := pubsub.New(&driver)
//	  pub, err := ps.Publish("my-agent", element)
//	  pub, err := ps.PublishPersistent("other-agent", element)
//	  sub, err := ps.Subscribe("my-agent", element, true, ctx)
//	}
//
// # Driver
//
// The driver is responsible for implementing the underlying mechanics of
// publishing and subscribing. While `pubsub.PubSub` and its components -
// `Publication` and `Subscription` - handle the in-memory and diff aspects,
// the driver itself is responsible for communicating between the publisher
// and subscriber, and performing any persistence.
//
// The driver is expected to implement the `Driver` interface, which primarily
// involves being able to return the `DriverPublisher` and `DriverSubscriber`.
// These in turn are used by `Publication` and `Subscription` to publish and
// subscribe messages.
//
// The `DriverPublisher` and `DriverSubscriber` are expected to function as
// follows.
//
// # DriverPublisher
//
// The `DriverPublisher` publishes messages and, optionally, persists them.
// It also can `Unpublish` messages, as well as `Load` all messages from
// persistence store. Finally, it must be able to set and clear a `restarted`
// flag/counter.
//
// The actual interface is key-value pairs, where it either is requested to
// publish a key (string) and value (`interface{}`), or unpublish a key.
//
// See the documentation for the `DriverPublisher` interface to learn more.
//
// # DriverSubscriber
//
// The `DriverSubscriber` subscribes to messages. As with the `DriverPublisher`,
// the caller has no understanding of the underlying mechanism or semantics.
// Once started, the subscriber is expected to send any changes to the channel
// which was passed to it at startup. These changes are in the format of
// `pubsub.Change`, which encapsulates the change operation, key and value.
//
// See the documentation for the `DriverSubscriber` interface to learn more.
package pubsub
