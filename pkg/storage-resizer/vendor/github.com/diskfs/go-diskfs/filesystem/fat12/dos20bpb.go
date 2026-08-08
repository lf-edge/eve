package fat12

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// MsdosMediaType is the (mostly unused) media type.
type MsdosMediaType uint8

const (
	// Media8InchDrDos for single-sided 250KB DR-DOS disks
	Media8InchDrDos MsdosMediaType = 0xe5
	// Media525InchTandy for 5.25 inch floppy disks for Tandy
	Media525InchTandy MsdosMediaType = 0xed
	// MediaCustomPartitionsDrDos for non-standard custom DR-DOS partitions
	MediaCustomPartitionsDrDos MsdosMediaType = 0xee
	// MediaCustomSuperFloppyDrDos for non-standard custom superfloppy disks for DR-DOS
	MediaCustomSuperFloppyDrDos MsdosMediaType = 0xef
	// Media35Inch for standard 1.44MB and 2.88MB 3.5 inch floppy disks
	Media35Inch MsdosMediaType = 0xf0
	// MediaDoubleDensityAltos for double-density floppy disks for Altos only
	MediaDoubleDensityAltos MsdosMediaType = 0xf4
	// MediaFixedDiskAltos for fixed disk 1.95MB for Altos only
	MediaFixedDiskAltos MsdosMediaType = 0xf5
	// MediaFixedDisk for standard fixed disks
	MediaFixedDisk MsdosMediaType = 0xf8
)

// SectorSize indicates what the sector size in bytes is
type SectorSize uint16

const (
	// SectorSize512 is a sector size of 512 bytes
	SectorSize512        SectorSize = 512
	bytesPerSlot         int        = 32
	maxCharsLongFilename int        = 13
)

// Dos20BPB is a DOS 2.0 BIOS Parameter Block structure, shared by FAT12, FAT16, and FAT32.
type Dos20BPB struct {
	BytesPerSector       SectorSize // always 512 for FAT12/16
	SectorsPerCluster    uint8
	ReservedSectors      uint16
	FatCount             uint8
	RootDirectoryEntries uint16 // non-zero for FAT12/FAT16; zero for FAT32
	TotalSectors         uint16 // non-zero if total sectors fit in 16 bits; else see Dos331BPB
	MediaType            uint8
	SectorsPerFat        uint16 // for FAT12/16; zero for FAT32 (see dos71EBPB)
}

// Dos20BPBFromBytes reads the DOS 2.0 BPB from exactly 13 bytes.
func Dos20BPBFromBytes(b []byte) (*Dos20BPB, error) {
	if len(b) != 13 {
		return nil, errors.New("cannot read DOS 2.0 BPB: must be exactly 13 bytes")
	}
	sectorSize := binary.LittleEndian.Uint16(b[0:2])
	if sectorSize < uint16(SectorSize512) || (sectorSize&(sectorSize-1)) != 0 {
		return nil, fmt.Errorf("invalid sector size %d: must be power of 2 and >= 512", sectorSize)
	}
	return &Dos20BPB{
		BytesPerSector:       SectorSize(sectorSize),
		SectorsPerCluster:    b[2],
		ReservedSectors:      binary.LittleEndian.Uint16(b[3:5]),
		FatCount:             b[5],
		RootDirectoryEntries: binary.LittleEndian.Uint16(b[6:8]),
		TotalSectors:         binary.LittleEndian.Uint16(b[8:10]),
		MediaType:            b[10],
		SectorsPerFat:        binary.LittleEndian.Uint16(b[11:13]),
	}, nil
}

// ToBytes serialises the DOS 2.0 BPB to 13 bytes.
func (bpb *Dos20BPB) ToBytes() []byte {
	b := make([]byte, 13)
	binary.LittleEndian.PutUint16(b[0:2], uint16(bpb.BytesPerSector))
	b[2] = bpb.SectorsPerCluster
	binary.LittleEndian.PutUint16(b[3:5], bpb.ReservedSectors)
	b[5] = bpb.FatCount
	binary.LittleEndian.PutUint16(b[6:8], bpb.RootDirectoryEntries)
	binary.LittleEndian.PutUint16(b[8:10], bpb.TotalSectors)
	b[10] = bpb.MediaType
	binary.LittleEndian.PutUint16(b[11:13], bpb.SectorsPerFat)
	return b
}
