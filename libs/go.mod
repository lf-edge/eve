module github.com/lf-edge/eve/libs

go 1.20

require github.com/onsi/gomega v1.24.2

require (
	github.com/golang-design/lockfree v0.0.1
	github.com/google/gopacket v1.1.19
	github.com/lithammer/shortuuid/v4 v4.0.0
	github.com/mdlayher/netlink v1.7.1
	github.com/packetcap/go-pcap v0.0.0-20221020071412-2b2e94010282
	github.com/sirupsen/logrus v1.9.0
	github.com/ti-mo/conntrack v0.4.0
	golang.org/x/net v0.7.0
	golang.org/x/sys v0.5.0
)

require (
	github.com/changkun/lockfree v0.0.1 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/josharian/native v1.0.0 // indirect
	github.com/mdlayher/socket v0.4.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/ti-mo/netfilter v0.3.1 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	cloud.google.com/go/storage v1.17.0
	github.com/Azure/azure-pipeline-go v0.2.3
	github.com/Azure/azure-storage-blob-go v0.14.0
	github.com/aws/aws-sdk-go v1.35.35
	github.com/google/go-containerregistry v0.6.0
	github.com/pkg/sftp v1.12.0
	golang.org/x/crypto v0.1.0
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f
	google.golang.org/api v0.57.0
)

require (
	cloud.google.com/go v0.94.1 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.7.0 // indirect
	github.com/docker/cli v20.10.7+incompatible // indirect
	github.com/docker/distribution v2.8.0+incompatible // indirect
	github.com/docker/docker v20.10.24+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.6.3 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.3 // indirect
	github.com/googleapis/gax-go/v2 v2.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/compress v1.13.0 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/mattn/go-ieproxy v0.0.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	go.opencensus.io v0.23.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20210921142501-181ce0d877f6 // indirect
	google.golang.org/grpc v1.40.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)

replace github.com/lf-edge/eve/api/go => ../../api/go
