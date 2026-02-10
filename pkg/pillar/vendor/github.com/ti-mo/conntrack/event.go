package conntrack

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

// Event holds information about a Conntrack event.
type Event struct {
	Type eventType

	Flow   *Flow
	Expect *Expect
}

// eventType is a custom type that describes the Conntrack event type.
type eventType uint8

// List of all types of Conntrack events. This is an internal representation
// unrelated to any message types in the kernel source.
const (
	EventUnknown eventType = iota
	EventNew
	EventUpdate
	EventDestroy
	EventExpNew
	EventExpDestroy
)

// unmarshal unmarshals a Conntrack EventType from a Netfilter header.
func (et *eventType) unmarshal(h netfilter.Header) error {
	// Fail when the message is not a conntrack message
	switch h.SubsystemID {
	case netfilter.NFSubsysCTNetlink:
		switch messageType(h.MessageType) {
		case ctNew:
			// Since the MessageType is only of kind new, get or delete,
			// the header's flags are used to distinguish between NEW and UPDATE.
			if h.Flags&(netlink.Create|netlink.Excl) != 0 {
				*et = EventNew
			} else {
				*et = EventUpdate
			}
		case ctDelete:
			*et = EventDestroy
		default:
			return fmt.Errorf("type %d: %w", h.MessageType, errUnknownEventType)
		}
	case netfilter.NFSubsysCTNetlinkExp:
		switch expMessageType(h.MessageType) {
		case ctExpNew:
			*et = EventExpNew
		case ctExpDelete:
			*et = EventExpDestroy
		default:
			return fmt.Errorf("type %d: %w", h.MessageType, errUnknownEventType)
		}
	default:
		return errNotConntrack
	}

	return nil
}

// Unmarshal unmarshals a Netlink message into an Event structure.
func (e *Event) Unmarshal(nlmsg netlink.Message) error {
	// Make sure we don't re-use an Event structure
	if e.Expect != nil || e.Flow != nil {
		return errReusedEvent
	}

	// Obtain the nlmsg's Netfilter header and AttributeDecoder.
	h, ad, err := netfilter.DecodeNetlink(nlmsg)
	if err != nil {
		return err
	}

	// Decode the header to make sure we're dealing with a Conntrack event.
	if err := e.Type.unmarshal(h); err != nil {
		return err
	}

	// Unmarshal Netfilter attributes into the event's Flow or Expect entry.
	switch id := h.SubsystemID; id {
	case netfilter.NFSubsysCTNetlink:
		var f Flow
		if err := f.unmarshal(ad); err != nil {
			return fmt.Errorf("unmarshal flow: %w", err)
		}
		e.Flow = &f
	case netfilter.NFSubsysCTNetlinkExp:
		var ex Expect
		if err := ex.unmarshal(ad); err != nil {
			return fmt.Errorf("unmarshal expect: %w", err)
		}
		e.Expect = &ex
	default:
		return fmt.Errorf("unmarshal message from non-conntrack subsystem: %s", id)
	}

	return nil
}
