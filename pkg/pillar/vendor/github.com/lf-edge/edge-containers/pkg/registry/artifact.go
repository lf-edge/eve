package registry

import "path"

type DiskType int

const (
	Raw DiskType = iota
	Vmdk
	Vhd
	ISO
	Qcow
	Qcow2
	Ova
	Vhdx
)

func (d DiskType) String() string {
	return [...]string{"Raw", "Vmdk", "Vhd", "ISO", "Qcow", "Qcow2", "Ova", "Vhdx"}[d]
}

// Source a source for an artifact component
type Source interface {
	// GetPath get path to a file, returns "" if no file
	GetPath() string
	// GetContent get the actual content if in memory, returns nil if in a file
	GetContent() []byte
	// GetName returns the target filename
	GetName() string
	// GetDigest returns the digest if provided directly; will not calculate for other sources.
	// Format is "sha256:<hash>"
	GetDigest() string
	// GetSize returns the size if provided directly; will not calculate for other sources.
	GetSize() int64
}

// FileSource implements a Source for a file
type FileSource struct {
	// Path path to the file source
	Path string
}

func (f *FileSource) GetPath() string {
	return f.Path
}
func (f *FileSource) GetContent() []byte {
	return nil
}
func (f *FileSource) GetName() string {
	return path.Base(f.Path)
}
func (f *FileSource) GetDigest() string {
	return ""
}
func (f *FileSource) GetSize() int64 {
	return 0
}

// MemorySource implements a Source for raw data
type MemorySource struct {
	// Content the data
	Content []byte
	// Name of file to save
	Name string
}

func (m *MemorySource) GetPath() string {
	return ""
}
func (m *MemorySource) GetContent() []byte {
	return m.Content
}
func (m *MemorySource) GetName() string {
	return m.Name
}
func (m *MemorySource) GetDigest() string {
	return ""
}
func (m *MemorySource) GetSize() int64 {
	return 0
}

// HashSource implements a source that has the hash directly, to enable creating a raw manifest
type HashSource struct {
	// Hash the sha256 hash
	Hash string
	// Name of file to save
	Name string
	// Size size of the target
	Size int64
}

func (h *HashSource) GetPath() string {
	return ""
}
func (h *HashSource) GetContent() []byte {
	return nil
}
func (h *HashSource) GetName() string {
	return h.Name
}
func (h *HashSource) GetDigest() string {
	return h.Hash
}
func (h *HashSource) GetSize() int64 {
	return h.Size
}

type Disk struct {
	Source Source
	Type   DiskType
}

type Artifact struct {
	// Kernel path to the kernel file
	Kernel Source
	// Initrd path to the initrd file
	Initrd Source
	// Config path to the config
	Config Source
	// Root path to the root disk and its type
	Root *Disk
	// Disks paths and types for additional disks
	Disks []*Disk
	// Other other items that did not have appropriate annotations
	Other []Source
}

var NameToType = map[string]DiskType{
	"raw":   Raw,
	"vmdk":  Vmdk,
	"vhd":   Vhd,
	"iso":   ISO,
	"qcow":  Qcow,
	"qcow2": Qcow2,
	"ova":   Ova,
	"vhdx":  Vhdx,
}
var TypeToMime = map[DiskType]string{
	Raw:   MimeTypeECIDiskRaw,
	Vhd:   MimeTypeECIDiskVhd,
	Vmdk:  MimeTypeECIDiskVmdk,
	ISO:   MimeTypeECIDiskISO,
	Qcow:  MimeTypeECIDiskQcow,
	Qcow2: MimeTypeECIDiskQcow2,
	Ova:   MimeTypeECIDiskOva,
	Vhdx:  MimeTypeECIDiskVhdx,
}
var MimeToType = map[string]DiskType{
	MimeTypeECIDiskRaw:   Raw,
	MimeTypeECIDiskVhd:   Vhd,
	MimeTypeECIDiskVmdk:  Vmdk,
	MimeTypeECIDiskISO:   ISO,
	MimeTypeECIDiskQcow:  Qcow,
	MimeTypeECIDiskQcow2: Qcow2,
	MimeTypeECIDiskOva:   Ova,
	MimeTypeECIDiskVhdx:  Vhdx,
}
