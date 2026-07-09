module github.com/lf-edge/eve/pkg/storage-resizer

go 1.25.7

require (
	github.com/diskfs/partitionresizer v1.0.1-0.20260619090936-1f93724e4407
	golang.org/x/sys v0.46.0
)

require (
	github.com/anchore/go-lzo v0.1.0 // indirect
	github.com/diskfs/go-diskfs v1.9.4-0.20260618163850-2bdff12e5d99 // indirect
	github.com/djherbis/times v1.6.0 // indirect
	github.com/elliotwutingfeng/asciiset v0.0.0-20260129054604-cfde2086bc57 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/pierrec/lz4/v4 v4.1.27 // indirect
	github.com/pkg/xattr v0.4.12 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/ulikunitz/xz v0.5.15 // indirect
)

replace github.com/diskfs/partitionresizer => github.com/eriknordmark/partitionresizer v0.0.0-20260708234439-358f8d8b78bb
