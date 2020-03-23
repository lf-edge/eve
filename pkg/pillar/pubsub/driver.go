package pubsub

// Driver a backend driver for pubsub
type Driver interface {
	// Publisher return a `DriverPublisher` for the given name and topic.
	// The caller passes the `Updaters`, `Restarted` checker and `Differ`.
	// These can be used to:
	// * add to or remove from the updaters
	// * determine if the topic has been restarted
	// * diff the current known state from the target known state
	Publisher(global bool, name, topic string, persistent bool, updaterList *Updaters, restarted Restarted, differ Differ) (DriverPublisher, error)
	// Subscriber return a `DriverSubscriber` for the given name and topic.
	// This is expected to create a `DriverSubscriber`, but not start it.
	// Once started, when changes arrive, they should be published to the provided
	// channel. Each update to the channel is of type `Change`, which encapsulates
	// the operation, key and value.
	Subscriber(global bool, name, topic string, persistent bool, C chan Change) (DriverSubscriber, error)
	// DefaultName Return the default name to use for an agent, when the name
	// is not provided.
	DefaultName() string
}

// DriverSubscriber interface that a driver for subscribing must implement
type DriverSubscriber interface {
	// Start subscribing to a name and topic and publish changes to the channel.
	// This is expected to return immediately. If it needs to run in the
	// background, it is the responsibility of the driver to run it as a separate
	// goroutine.
	Start() error
}

// DriverPublisher interface that a driver for publishing must implement
type DriverPublisher interface {
	// Start the publisher, if any startup is necessary.
	// This is expected to return immediately. If it needs to run in the
	// background, it is the responsibility of the driver to run it as a separate
	// goroutine.
	Start() error
	// Load current status from persistence. Usually called only on first start.
	// The implementation is responsible for determining if the load is necessary
	// or already has been performed. If it has been already, it should not change
	// anything. The caller has no knowledge of where the persistent state was
	// stored: disk, databases, or vellum. All it cares about is that it gets
	// a key-value list.
	Load() (map[string][]byte, bool, error)
	// Publish a key-value pair to all subscribers and optionally persistence
	Publish(key string, item []byte) error
	// Unpublish a key, i.e. delete it and publish its deletion to all subscribers
	Unpublish(key string) error
	// Restart set the state of the topic to restarted, or cancel the restarted
	// state
	Restart(restarted bool) error
}

// Restarted interface that lets you determine if a Publication has been restarted
type Restarted interface {
	IsRestarted() bool
}

// Differ interface that updates a LocalCollection from previous state to current state,
// and returns a slice of keys that have changed
type Differ interface {
	DetermineDiffs(slaveCollection LocalCollection) []string
}
