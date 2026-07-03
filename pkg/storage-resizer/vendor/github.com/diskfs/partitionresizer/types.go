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
	name   string
	label  string
	size   int64 // in bytes
	start  int64 // in bytes
	end    int64 // in bytes
	number int
	uuid   string
}

type partitionResizeTarget struct {
	original partitionData
	target   partitionData
}
