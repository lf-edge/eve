// Stub file to make nl package compile on macos
// +build darwin

package nl

import (
	"sync"
)

// Only the definations needed for compilation on MacOs are added here.
// When adding the definitions, copy the corresponding ones from
//	nl_linux.go
type NetlinkRequestData interface {
	Len() int
	Serialize() []byte
}

type NetlinkRequest struct {
	//unix.NlMsghdr
	Data    []NetlinkRequestData
	RawData []byte
	//Sockets map[int]*SocketHandle
}

type NetlinkSocket struct {
	fd int32
	//lsa unix.SockaddrNetlink
	sync.Mutex
}
