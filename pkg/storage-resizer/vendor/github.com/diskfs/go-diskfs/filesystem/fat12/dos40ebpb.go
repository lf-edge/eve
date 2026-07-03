package fat12

import (
	"encoding/binary"
	"fmt"
	"regexp"
)

const (
	shortEBPB uint8 = 0x28
	longEBPB  uint8 = 0x29
)

// Dos40EBPB is the Extended BIOS Parameter Block used by FAT12 and FAT16.
// It wraps the DOS 3.31 BPB and adds drive identification, volume serial number,
// volume label, and filesystem type string.
type Dos40EBPB struct {
	Dos331BPB          *Dos331BPB
	DriveNumber        uint8
	ReservedFlags      uint8
	ExtBootSignature   uint8 // 0x28 (short) or 0x29 (long, includes label+type)
	VolumeSerialNumber uint32
	VolumeLabel        string // 11 bytes, padded with spaces; only present when ExtBootSignature == 0x29
	FileSystemType     string // 8 bytes, e.g. "FAT12   " or "FAT16   "; only when 0x29
}

// Dos40EBPBFromBytes parses a Dos40EBPB from a byte slice.
// The slice must be at least 26 bytes (short form) or 51 bytes (long form).
// Returns the parsed struct and the number of bytes consumed.
func Dos40EBPBFromBytes(b []byte) (*Dos40EBPB, int, error) {
	if len(b) < 26 {
		return nil, 0, fmt.Errorf("cannot parse Dos40EBPB: need at least 26 bytes, got %d", len(b))
	}
	dos331, err := Dos331BPBFromBytes(b[0:25])
	if err != nil {
		return nil, 0, fmt.Errorf("error reading embedded DOS 3.31 BPB: %w", err)
	}
	bpb := &Dos40EBPB{
		Dos331BPB:          dos331,
		DriveNumber:        b[25],
		ReservedFlags:      b[26],
		ExtBootSignature:   b[27],
		VolumeSerialNumber: binary.LittleEndian.Uint32(b[28:32]),
	}
	switch bpb.ExtBootSignature {
	case shortEBPB:
		return bpb, 32, nil
	case longEBPB:
		if len(b) < 51 {
			return nil, 0, fmt.Errorf("cannot parse long Dos40EBPB: need 51 bytes, got %d", len(b))
		}
		re := regexp.MustCompile(` +$`)
		bpb.VolumeLabel = re.ReplaceAllString(string(b[32:43]), "")
		bpb.FileSystemType = re.ReplaceAllString(string(b[43:51]), "")
		return bpb, 51, nil
	default:
		return nil, 0, fmt.Errorf("unknown extended boot signature: 0x%02x", bpb.ExtBootSignature)
	}
}

// ToBytes serialises the Dos40EBPB. Returns an error if the volume label or
// filesystem type strings are too long or contain non-ASCII characters.
func (bpb *Dos40EBPB) ToBytes() ([]byte, error) {
	var size int
	switch bpb.ExtBootSignature {
	case shortEBPB:
		size = 32
	case longEBPB:
		size = 51
	default:
		return nil, fmt.Errorf("unknown extended boot signature: 0x%02x", bpb.ExtBootSignature)
	}
	b := make([]byte, size)
	copy(b[0:25], bpb.Dos331BPB.ToBytes())
	b[25] = bpb.DriveNumber
	b[26] = bpb.ReservedFlags
	b[27] = bpb.ExtBootSignature
	binary.LittleEndian.PutUint32(b[28:32], bpb.VolumeSerialNumber)
	if bpb.ExtBootSignature == longEBPB {
		label := bpb.VolumeLabel
		if len(label) > 11 {
			return nil, fmt.Errorf("volume label too long: %d chars, max 11", len(label))
		}
		copy(b[32:43], fmt.Sprintf("%-11s", label))
		fstype := bpb.FileSystemType
		if len(fstype) > 8 {
			return nil, fmt.Errorf("filesystem type too long: %d chars, max 8", len(fstype))
		}
		copy(b[43:51], fmt.Sprintf("%-8s", fstype))
	}
	return b, nil
}

// equal compares two Dos40EBPB values.
func (bpb *Dos40EBPB) equal(a *Dos40EBPB) bool {
	if (bpb == nil) != (a == nil) {
		return false
	}
	if bpb == nil {
		return true
	}
	return bpb.Dos331BPB.Equal(a.Dos331BPB) &&
		bpb.DriveNumber == a.DriveNumber &&
		bpb.ReservedFlags == a.ReservedFlags &&
		bpb.ExtBootSignature == a.ExtBootSignature &&
		bpb.VolumeSerialNumber == a.VolumeSerialNumber &&
		bpb.VolumeLabel == a.VolumeLabel &&
		bpb.FileSystemType == a.FileSystemType
}

// TotalSectors returns the effective total sector count, preferring the 32-bit field.
func (bpb *Dos40EBPB) TotalSectors() uint32 {
	if bpb.Dos331BPB.TotalSectors32 != 0 {
		return bpb.Dos331BPB.TotalSectors32
	}
	return uint32(bpb.Dos331BPB.Dos20BPB.TotalSectors)
}

// Dos40EBPBFromBytesOnly is a convenience wrapper around Dos40EBPBFromBytes that
// discards the consumed-byte count. Useful when the caller does not need to know
// where the BPB ends (e.g. when only reading, not writing).
func Dos40EBPBFromBytesOnly(b []byte) (*Dos40EBPB, error) {
	bpb, _, err := Dos40EBPBFromBytes(b)
	return bpb, err
}
