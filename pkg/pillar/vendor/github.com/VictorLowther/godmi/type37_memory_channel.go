/*
* File Name:	type37_memory_channel.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-20
*/
package godmi

import (
	"fmt"
)

type MemoryChannelType byte

const (
	MemoryChannelTypeOther MemoryChannelType = 1 + iota
	MemoryChannelTypeUnknown
	MemoryChannelTypeRamBus
	MemoryChannelTypeSyncLink
)

func (m MemoryChannelType) String() string {
	types := [...]string{
		"Other",
		"Unknown",
		"RamBus",
		"SyncLink",
	}
	return types[m-1]
}

type MemoryDeviceLoadHandle struct {
	Load   byte
	Handle uint16
}

type MemoryDeviceLoadHandles []MemoryDeviceLoadHandle

func newMemoryDeviceLoadHandles(data []byte, count byte, length byte) MemoryDeviceLoadHandles {
	md := make([]MemoryDeviceLoadHandle, 0)
	if length < 0x07+count {
		return md
	}
	for i := byte(1); i <= count; i++ {
		var mem MemoryDeviceLoadHandle
		offset := 3 * (i - 1)
		mem.Load = data[0x07+offset]
		mem.Handle = u16(data[0x08+offset : 0x0A+offset])
		md = append(md, mem)
	}
	return md
}

func (m MemoryDeviceLoadHandles) String() string {
	var s string
	for _, md := range m {
		s += fmt.Sprintf("\n\t\tDevice: %d\tHandle %d", md.Load, md.Handle)
	}
	return s
}

type MemoryChannel struct {
	infoCommon
	ChannelType        MemoryChannelType
	MaximumChannelLoad byte
	MemoryDeviceCount  byte
	LoadHandle         MemoryDeviceLoadHandles
}

func (m MemoryChannel) String() string {
	return fmt.Sprintf("Memory Channel\n"+
		"\tChannel Type: %s\n"+
		"\tMaximum Channel Load: %d\n"+
		"%s",
		m.ChannelType,
		m.MaximumChannelLoad,
		m.LoadHandle)
}

