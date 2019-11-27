package pubsub

type Operation byte

const (
	Restart Operation = iota
	Create
	Delete
	Modify
)

// Change the message to go into a change channel
type Change struct {
	Operation Operation
	Key       string
	Value     interface{}
}
