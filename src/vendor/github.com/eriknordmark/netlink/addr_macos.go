// build +darwin

// Only the definations needed for compilation on MacOs are added here.
// When adding the definitions, copy the corresponding ones from
//	addr_linux.go
package netlink

import (
	"net"
)

type AddrUpdate struct {
	LinkAddress net.IPNet
	LinkIndex   int
	Flags       int
	Scope       int
	PreferedLft int
	ValidLft    int
	NewAddr     bool // true=added false=deleted
}
