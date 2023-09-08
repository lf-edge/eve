package uevent

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// Uevent represents a single uevent.
type Uevent struct {
	Header string

	// default uevent variables as per kobject_uevent.c
	Action    string
	Devpath   string
	Subsystem string
	Seqnum    string

	// A key/value map of all variables
	Vars map[string]string
}

// Decoder decodes uevents from a reader.
type Decoder struct {
	r *bufio.Reader
}

// NewDecoder creates an uevent decoder
// using the given reader to read uevents from.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{bufio.NewReader(r)}
}

// Decode blocks until the uext uevent happens, decodes and returns it.
// It is meant to be used in a loop.
func (d *Decoder) Decode() (*Uevent, error) {
	ev := &Uevent{
		Vars: map[string]string{},
	}

	h, err := d.next()
	if err != nil {
		return nil, err
	}
	ev.Header = h

loop:
	for {
		kv, err := d.next()
		if err != nil {
			return nil, err
		}

		i := strings.Index(kv, "=")
		if i < 0 {
			return nil, errors.New("error decoding uevent: unknown format")
		}

		k, v := kv[:i], kv[i+1:len(kv)-1] // last char is zero (0)
		ev.Vars[k] = v

		switch k {
		case "ACTION":
			ev.Action = v
		case "DEVPATH":
			ev.Devpath = v
		case "SUBSYSTEM":
			ev.Subsystem = v
		case "SEQNUM": // implicitely signals a complete uevent
			ev.Seqnum = v
			break loop
		}
	}

	return ev, nil
}

// next returns the next event token
func (d *Decoder) next() (string, error) {
	s, err := d.r.ReadString(0x00)
	if err != nil {
		return "", err
	}
	return s, nil
}
