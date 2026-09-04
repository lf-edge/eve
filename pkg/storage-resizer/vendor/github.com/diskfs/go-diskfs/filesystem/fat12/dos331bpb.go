package fat12

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Dos331BPB is the DOS 3.31 BIOS Parameter Block, shared by FAT12, FAT16, and FAT32.
type Dos331BPB struct {
	Dos20BPB        *Dos20BPB
	SectorsPerTrack uint16
	Heads           uint16
	HiddenSectors   uint32
	TotalSectors32  uint32 // used when TotalSectors in Dos20BPB is 0
}

// Dos331BPBFromBytes reads the DOS 3.31 BPB from exactly 25 bytes.
func Dos331BPBFromBytes(b []byte) (*Dos331BPB, error) {
	if len(b) != 25 {
		return nil, errors.New("cannot read DOS 3.31 BPB: must be exactly 25 bytes")
	}
	dos20, err := Dos20BPBFromBytes(b[0:13])
	if err != nil {
		return nil, fmt.Errorf("error reading embedded DOS 2.0 BPB: %w", err)
	}
	return &Dos331BPB{
		Dos20BPB:        dos20,
		SectorsPerTrack: binary.LittleEndian.Uint16(b[13:15]),
		Heads:           binary.LittleEndian.Uint16(b[15:17]),
		HiddenSectors:   binary.LittleEndian.Uint32(b[17:21]),
		TotalSectors32:  binary.LittleEndian.Uint32(b[21:25]),
	}, nil
}

// ToBytes serialises the DOS 3.31 BPB to 25 bytes.
func (bpb *Dos331BPB) ToBytes() []byte {
	b := make([]byte, 25)
	copy(b[0:13], bpb.Dos20BPB.ToBytes())
	binary.LittleEndian.PutUint16(b[13:15], bpb.SectorsPerTrack)
	binary.LittleEndian.PutUint16(b[15:17], bpb.Heads)
	binary.LittleEndian.PutUint32(b[17:21], bpb.HiddenSectors)
	binary.LittleEndian.PutUint32(b[21:25], bpb.TotalSectors32)
	return b
}

// Equal compares two Dos331BPB values.
func (bpb *Dos331BPB) Equal(a *Dos331BPB) bool {
	if (bpb == nil) != (a == nil) {
		return false
	}
	if bpb == nil {
		return true
	}
	return bpb.Dos20BPB != nil && a.Dos20BPB != nil &&
		*bpb.Dos20BPB == *a.Dos20BPB &&
		bpb.SectorsPerTrack == a.SectorsPerTrack &&
		bpb.Heads == a.Heads &&
		bpb.HiddenSectors == a.HiddenSectors &&
		bpb.TotalSectors32 == a.TotalSectors32
}
