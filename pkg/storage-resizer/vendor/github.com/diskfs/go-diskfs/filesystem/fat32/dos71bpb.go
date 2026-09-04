package fat32

import (
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"

	"github.com/diskfs/go-diskfs/filesystem/fat12"
)

const (
	// shortDos71EBPB indicates that a DOS 7.1 EBPB is of the short 60-byte format
	shortDos71EBPB uint8 = 0x28
	// longDos71EBPB indicates that a DOS 7.1 EBPB is of the long 79-byte format
	longDos71EBPB uint8 = 0x29
)

const (
	// fileSystemTypeFAT32 is the fixed string representation for the FAT32 filesystem type
	fileSystemTypeFAT32 string = "FAT32   "
)

// fatVersion is the version of the FAT filesystem
type fatVersion uint16

const (
	// fatVersion0 represents version 0 of FAT, the only acceptable version
	fatVersion0 fatVersion = 0
)

const (
	// FirstRemovableDrive is first removable drive
	FirstRemovableDrive uint8 = 0x00
	// FirstFixedDrive is first fixed drive
	FirstFixedDrive uint8 = 0x80
)

// dos71EBPB is the DOS 7.1 Extended BIOS Parameter Block used by FAT32.
// The embedded DOS 3.31 BPB is shared with FAT12/16 and lives in fat12.Dos331BPB.
type dos71EBPB struct {
	Dos331BPB             *fat12.Dos331BPB
	sectorsPerFat         uint32
	mirrorFlags           uint16
	version               fatVersion
	rootDirectoryCluster  uint32
	fsInformationSector   uint16
	backupBootSector      uint16
	bootFileName          [12]byte
	driveNumber           uint8
	reservedFlags         uint8
	extendedBootSignature uint8
	volumeSerialNumber    uint32
	volumeLabel           string
	fileSystemType        string
}

func (bpb *dos71EBPB) equal(a *dos71EBPB) bool {
	if (bpb == nil && a != nil) || (a == nil && bpb != nil) {
		return false
	}
	if bpb == nil && a == nil {
		return true
	}
	return bpb.Dos331BPB.Equal(a.Dos331BPB) &&
		bpb.sectorsPerFat == a.sectorsPerFat &&
		bpb.mirrorFlags == a.mirrorFlags &&
		bpb.version == a.version &&
		bpb.rootDirectoryCluster == a.rootDirectoryCluster &&
		bpb.fsInformationSector == a.fsInformationSector &&
		bpb.backupBootSector == a.backupBootSector &&
		bpb.bootFileName == a.bootFileName &&
		bpb.driveNumber == a.driveNumber &&
		bpb.reservedFlags == a.reservedFlags &&
		bpb.extendedBootSignature == a.extendedBootSignature &&
		bpb.volumeSerialNumber == a.volumeSerialNumber &&
		bpb.volumeLabel == a.volumeLabel &&
		bpb.fileSystemType == a.fileSystemType
}

// dos71EBPBFromBytes reads the FAT32 Extended BIOS Parameter Block from a slice of bytes.
func dos71EBPBFromBytes(b []byte) (*dos71EBPB, int, error) {
	if b == nil || (len(b) != 60 && len(b) != 79) {
		return nil, 0, errors.New("cannot read DOS 7.1 EBPB from invalid byte slice, must be precisely 60 or 79 bytes ")
	}
	bpb := dos71EBPB{}
	size := 0

	dos331bpb, err := fat12.Dos331BPBFromBytes(b[0:25])
	if err != nil {
		return nil, 0, fmt.Errorf("could not read embedded DOS 3.31 BPB: %v", err)
	}
	bpb.Dos331BPB = dos331bpb

	bpb.sectorsPerFat = binary.LittleEndian.Uint32(b[25:29])
	bpb.mirrorFlags = binary.LittleEndian.Uint16(b[29:31])
	version := binary.LittleEndian.Uint16(b[31:33])
	if version != uint16(fatVersion0) {
		return nil, size, fmt.Errorf("invalid FAT32 version found: %v", version)
	}
	bpb.version = fatVersion0
	bpb.rootDirectoryCluster = binary.LittleEndian.Uint32(b[33:37])
	bpb.fsInformationSector = binary.LittleEndian.Uint16(b[37:39])
	bpb.backupBootSector = binary.LittleEndian.Uint16(b[39:41])
	copy(bpb.bootFileName[:], b[41:53])
	bpb.driveNumber = b[53]
	bpb.reservedFlags = b[54]
	extendedSignature := b[55]
	bpb.extendedBootSignature = extendedSignature
	bpb.volumeSerialNumber = binary.BigEndian.Uint32(b[56:60])

	switch extendedSignature {
	case shortDos71EBPB:
		size = 60
	case longDos71EBPB:
		size = 79
		re := regexp.MustCompile(" +$")
		bpb.volumeLabel = re.ReplaceAllString(string(b[60:71]), "")
		bpb.fileSystemType = re.ReplaceAllString(string(b[71:79]), "")
	default:
		return nil, size, fmt.Errorf("unknown DOS 7.1 EBPB Signature: %v", extendedSignature)
	}

	return &bpb, size, nil
}

// toBytes returns the Extended BIOS Parameter Block as bytes ready to write to disk.
func (bpb *dos71EBPB) toBytes() ([]byte, error) {
	var b []byte
	switch bpb.extendedBootSignature {
	case shortDos71EBPB:
		b = make([]byte, 60)
	case longDos71EBPB:
		b = make([]byte, 79)
		label := bpb.volumeLabel
		if len(label) > 11 {
			return nil, fmt.Errorf("invalid volume label: too long at %d characters, maximum is %d", len(label), 11)
		}
		if len([]rune(label)) != len(label) {
			return nil, fmt.Errorf("invalid volume label: non-ascii characters")
		}
		copy(b[60:71], fmt.Sprintf("%-11s", label))
		fstype := bpb.fileSystemType
		if len(fstype) > 8 {
			return nil, fmt.Errorf("invalid filesystem type: too long at %d characters, maximum is %d", len(fstype), 8)
		}
		if len([]rune(fstype)) != len(fstype) {
			return nil, fmt.Errorf("invalid filesystem type: non-ascii characters")
		}
		copy(b[71:79], fmt.Sprintf("%-11s", fstype))
	default:
		return nil, fmt.Errorf("unknown DOS 7.1 EBPB Signature: %v", bpb.extendedBootSignature)
	}
	dos331Bytes := bpb.Dos331BPB.ToBytes()
	copy(b[0:25], dos331Bytes)
	binary.LittleEndian.PutUint32(b[25:29], bpb.sectorsPerFat)
	binary.LittleEndian.PutUint16(b[29:31], bpb.mirrorFlags)
	binary.LittleEndian.PutUint16(b[31:33], uint16(bpb.version))
	binary.LittleEndian.PutUint32(b[33:37], bpb.rootDirectoryCluster)
	binary.LittleEndian.PutUint16(b[37:39], bpb.fsInformationSector)
	binary.LittleEndian.PutUint16(b[39:41], bpb.backupBootSector)
	copy(b[41:53], bpb.bootFileName[:])
	b[53] = bpb.driveNumber
	b[54] = bpb.reservedFlags
	b[55] = bpb.extendedBootSignature
	binary.BigEndian.PutUint32(b[56:60], bpb.volumeSerialNumber)
	return b, nil
}
