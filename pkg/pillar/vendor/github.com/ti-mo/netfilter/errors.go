package netfilter

import (
	"errors"
)

var (
	// errInvalidAttributeFlags specifies if an Attribute's flag configuration is invalid.
	// From a comment in Linux/include/uapi/linux/netlink.h, Nested and NetByteOrder are mutually exclusive.
	errInvalidAttributeFlags = errors.New("invalid attribute; type cannot have both nested and net byte order flags")

	errMessageLen = errors.New("expected at least 4 bytes in netlink message payload")

	errConnIsMulticast = errors.New("Conn is attached to one or more multicast groups and can no longer be used for bidirectional traffic")

	errNoMulticastGroups = errors.New("need one or more multicast groups to join")

	errNilAttributeEncoder = errors.New("given AttributeEncoder is nil")
)
