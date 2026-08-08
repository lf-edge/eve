package pubsub

// Operation type for a single change operation
type Operation byte

const (
	// Restart operation is a restart
	Restart Operation = iota
	// Sync operation is a complete/sync of the initial content
	Sync
	// Delete operation is delete an existing key
	Delete
	// Modify operation is modify the value of an existing key
	Modify
)

// Change the message to go into a change channel
type Change struct {
	// Operation which operation is performed by this change
	Operation Operation
	// Key the key of the affected item, if any
	Key string
	// Value the value of the affected item, if any
	Value []byte
}
