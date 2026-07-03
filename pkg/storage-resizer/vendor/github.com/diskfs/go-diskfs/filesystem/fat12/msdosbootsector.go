package fat12

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const msDosBootSectorSignature uint16 = 0x55aa

// msDosBootSector represents the 512-byte FAT12/FAT16 boot sector.
type msDosBootSector struct {
	jumpInstruction    [3]byte
	oemName            string
	biosParameterBlock *Dos40EBPB
	bootCode           []byte
}

func (m *msDosBootSector) equal(a *msDosBootSector) bool {
	if (m == nil) != (a == nil) {
		return false
	}
	if m == nil {
		return true
	}
	return m.biosParameterBlock.equal(a.biosParameterBlock) &&
		m.oemName == a.oemName &&
		m.jumpInstruction == a.jumpInstruction &&
		bytes.Equal(m.bootCode, a.bootCode)
}

// msDosBootSectorFromBytes parses the 512-byte boot sector for FAT12/16.
func msDosBootSectorFromBytes(b []byte) (*msDosBootSector, error) {
	if len(b) != int(SectorSize512) {
		return nil, fmt.Errorf("boot sector must be exactly %d bytes, got %d", SectorSize512, len(b))
	}
	bs := &msDosBootSector{}
	copy(bs.jumpInstruction[:], b[0:3])
	bs.oemName = string(b[3:11])

	bpb, bpbSize, err := Dos40EBPBFromBytes(b[11:])
	if err != nil {
		return nil, fmt.Errorf("error parsing Dos40EBPB: %w", err)
	}
	bs.biosParameterBlock = bpb

	bootStart := 11 + bpbSize
	bootEnd := int(SectorSize512) - 2
	bs.bootCode = b[bootStart:bootEnd]

	if sig := binary.BigEndian.Uint16(b[bootEnd:]); sig != msDosBootSectorSignature {
		return nil, fmt.Errorf("invalid boot sector signature: 0x%04x", sig)
	}
	return bs, nil
}

// toBytes serialises the boot sector to 512 bytes.
func (m *msDosBootSector) toBytes() ([]byte, error) {
	b := make([]byte, SectorSize512)
	copy(b[0:3], m.jumpInstruction[:])
	name := m.oemName
	if len(name) > 8 {
		return nil, fmt.Errorf("OEM name too long: %s", name)
	}
	copy(b[3:11], fmt.Sprintf("%-8s", name))

	bpbBytes, err := m.biosParameterBlock.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("error serialising BPB: %w", err)
	}
	copy(b[11:], bpbBytes)
	bpbLen := len(bpbBytes)

	bootEnd := int(SectorSize512) - 2
	if len(m.bootCode) > bootEnd-(11+bpbLen) {
		return nil, fmt.Errorf("boot code too long: %d bytes", len(m.bootCode))
	}
	copy(b[11+bpbLen:bootEnd], m.bootCode)
	binary.BigEndian.PutUint16(b[bootEnd:], msDosBootSectorSignature)
	return b, nil
}
