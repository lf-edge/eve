package pubsub

import "fmt"

// Operation type for a single change operation
type Operation byte

const (
	// Restart operation is a restart
	Restart Operation = iota
	// Create operation is create a new key
	Create
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

// String returns string representation of Change object
func (change Change) String() string {
	operation := ""
	switch change.Operation {
	case Restart:
		operation = "Restart"
	case Create:
		operation = "Create"
	case Delete:
		operation = "Delete"
	case Modify:
		operation = "Modify"
	}
	return fmt.Sprintf("operation %s key %s val %s", operation, change.Key, string(change.Value))
}
