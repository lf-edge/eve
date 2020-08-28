module github.com/lf-edge/eve/pkg/pillar

go 1.12

require (
	github.com/Azure/azure-sdk-for-go v38.0.0+incompatible
	github.com/Azure/go-autorest/autorest v0.10.0 // indirect
	github.com/Microsoft/hcsshim v0.8.7 // indirect
	github.com/VictorLowther/godmi v0.0.0-20190311134151-270258a8252d // indirect
	github.com/aws/aws-sdk-go v1.27.1
	github.com/containerd/cgroups v0.0.0-20190919134610-bf292b21730f
	github.com/containerd/containerd v1.3.4
	github.com/containerd/continuity v0.0.0-20200228182428-0f16d7a0959c // indirect
	github.com/containerd/fifo v0.0.0-20191213151349-ff969a566b00 // indirect
	github.com/containerd/ttrpc v0.0.0-20200121165050-0be804eadb15 // indirect
	github.com/containerd/typeurl v0.0.0-20200205145503-b45ef1f1f737
	github.com/cshari-zededa/eve-tpm2-tools v0.0.4
	github.com/digitalocean/go-libvirt v0.0.0-20190715144809-7b622097a793 // indirect
	github.com/digitalocean/go-qemu v0.0.0-20181112162955-dd7bb9c771b8
	github.com/docker/docker v1.4.2-0.20190924003213-a8608b5b67c7
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/eriknordmark/ipinfo v0.0.0-20190220084921-7ee0839158f9
	github.com/eriknordmark/netlink v0.0.0-20190912172510-3b6b45309321
	github.com/fsnotify/fsnotify v1.4.7
	github.com/go-logfmt/logfmt v0.4.0 // indirect
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/gogo/googleapis v1.3.2 // indirect
	github.com/golang/protobuf v1.4.0-rc.4.0.20200313231945-b860323f09d0
	github.com/google/go-cmp v0.4.0
	github.com/google/go-containerregistry v0.0.0-20200430153450-5cbd060f5c92
	github.com/google/go-tpm v0.3.0
	github.com/google/gopacket v1.1.17
	github.com/gorilla/websocket v1.4.0
	github.com/jackwakefield/gopac v1.0.2
	github.com/kr/fs v0.1.0 // indirect
	github.com/lf-edge/eve/api/go v0.0.0-00010101000000-000000000000
	github.com/ochapman/godmi v0.0.0-20140902235245-2527e2081a16 // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1
	github.com/opencontainers/image-spec v1.0.1
	github.com/opencontainers/runc v0.1.1 // indirect
	github.com/opencontainers/runtime-spec v1.0.2
	github.com/packetcap/go-pcap v0.0.0-20200802095634-4c3b9511add7
	github.com/pkg/sftp v1.10.0
	github.com/rackn/gohai v0.0.0-20190321191141-5053e7f1fa36
	github.com/robertkrimen/otto v0.0.0-20180617131154-15f95af6e78d // indirect
	github.com/satori/go.uuid v1.2.0
	github.com/shirou/gopsutil v0.0.0-20190323131628-2cbc9195c892
	github.com/sirupsen/logrus v1.5.0
	github.com/stretchr/testify v1.4.0
	github.com/syndtr/gocapability v0.0.0-20180916011248-d98352740cb2 // indirect
	github.com/tatsushid/go-fastping v0.0.0-20160109021039-d7bb493dee3e
	github.com/vishvananda/netlink v1.0.1-0.20190823182904-a1c9a648f744 // indirect
	github.com/vishvananda/netns v0.0.0-20190625233234-7109fa855b0f // indirect
	golang.org/x/crypto v0.0.0-20200220183623-bac4c82f6975
	golang.org/x/net v0.0.0-20200324143707-d3edc9973b7e
	golang.org/x/sys v0.0.0-20200331124033-c3d80250170d
	google.golang.org/protobuf v1.21.0 // indirect
	gopkg.in/mcuadros/go-syslog.v2 v2.3.0
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
)

replace github.com/lf-edge/eve/api/go => ../../api/go

replace github.com/vishvananda/netlink/nl => github.com/eriknordmark/netlink/nl v0.0.0-20190903203740-41fa442996b8

replace github.com/vishvananda/netlink => github.com/eriknordmark/netlink v0.0.0-20190903203740-41fa442996b8

replace git.apache.org/thrift.git => github.com/apache/thrift v0.12.0

// because containerd
replace github.com/docker/distribution => github.com/docker/distribution v0.0.0-20190205005809-0d3efadf0154
