package partitionresizer

type Identifier string

const (
	IdentifierByName  Identifier = "name"
	IdentifierByLabel Identifier = "label"
	IdentifierByUUID  Identifier = "uuid"
)

type PartitionIdentifier interface {
	By() Identifier
	Value() string
}

type PartitionChange interface {
	PartitionIdentifier
	Size() int64 // in bytes
}

func NewPartitionIdentifier(by Identifier, value string) PartitionIdentifier {
	return &partitionIdentifierImpl{
		by:    by,
		value: value,
	}
}

func NewPartitionChange(by Identifier, value string, size int64) PartitionChange {
	return &partitionChangeImpl{
		identifier: NewPartitionIdentifier(by, value),
		size:       size,
	}
}

type partitionIdentifierImpl struct {
	by    Identifier
	value string
}

func (p *partitionIdentifierImpl) By() Identifier {
	return p.by
}
func (p *partitionIdentifierImpl) Value() string {
	return p.value
}

type partitionChangeImpl struct {
	identifier PartitionIdentifier
	size       int64 // in bytes
}

func (p *partitionChangeImpl) By() Identifier {
	return p.identifier.By()
}

func (p *partitionChangeImpl) Value() string {
	return p.identifier.Value()
}
func (p *partitionChangeImpl) Size() int64 {
	return p.size
}

type partitionData struct {
	name     string
	label    string
	size     int64 // in bytes
	start    int64 // in bytes
	end      int64 // in bytes
	number   int
	uuid     string
	typeGUID string // GPT partition type GUID; only carried for create targets
}

type partitionResizeTarget struct {
	original partitionData
	target   partitionData
	// create marks a target that has no source partition: it is allocated in
	// free space and, if fsType != FSNone, formatted with an empty filesystem.
	// Its GPT entry is published only by the final updatePartitions write.
	create bool
	fsType FSType
}

// FSType selects the filesystem laid down on a created (sourceless) partition.
// It is ignored for grows, whose content is copied from the source partition.
type FSType int

const (
	// FSNone leaves a created partition's contents untouched (raw).
	FSNone FSType = iota
	// FSFAT32 formats a created partition as an empty FAT32 filesystem.
	FSFAT32
	// FSExt4 formats a created partition as an empty ext4 filesystem.
	FSExt4
)

// PartitionSpec declares a partition that must exist with the given identity
// and at least MinSize bytes. It is monotonically non-destructive: an absent
// partition is created, a smaller one is grown, and one already at least
// MinSize is left unchanged (never shrunk). A matching partition is located by
// GUID; its type and label are asserted against the spec. Index requests a
// specific GPT partition number (0 = lowest free).
type PartitionSpec struct {
	Label    string
	TypeGUID string
	GUID     string
	Index    int
	MinSize  int64
	FS       FSType
}

// ShrinkSpec is the sole destructive operation: it permits shrinking the one
// identified partition to at most Size bytes to free space for the desired
// partitions. It is optional; when nil, no partition may be shrunk, so a
// grow+create-only invocation cannot shrink anything by accident.
type ShrinkSpec struct {
	ID   PartitionIdentifier
	Size int64
}
