package partitionresizer

import "fmt"

type InsufficientSpaceError struct {
	Partition string
	Requested int64
}

func (e *InsufficientSpaceError) Error() string {
	return fmt.Sprintf("not enough free space to resize partition %s to requested size %d", e.Partition, e.Requested)
}

func NewInsufficientSpaceError(partition string, requested int64) error {
	return &InsufficientSpaceError{
		Partition: partition,
		Requested: requested,
	}
}
