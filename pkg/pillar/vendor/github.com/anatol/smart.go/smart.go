package smart

import (
	"errors"
	"fmt"
)

// ErrOSUnsupported is returned on unsupported operating systems.
var ErrOSUnsupported = errors.New("os not supported")

type Device interface {
	Type() string
	Close() error
}

func Open(path string) (Device, error) {
	n, err := OpenNVMe(path)
	if err == nil {
		_, _, err := n.Identify()
		if err == nil {
			return n, nil
		}
		n.Close()
	}

	a, err := OpenSata(path)
	if err == nil {
		return a, nil
	}

	s, err := OpenScsi(path)
	if err == nil {
		return s, nil
	}

	return nil, fmt.Errorf("unknown drive type")
}
