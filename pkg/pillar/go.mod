module github.com/lf-edge/eve/pkg/pillar

go 1.15

require (
	github.com/Shopify/logrus-bugsnag v0.0.0-20171204204709-577dee27f20d // indirect
	github.com/VictorLowther/godmi v0.0.0-20190311134151-270258a8252d // indirect
	github.com/bitly/go-simplejson v0.5.0 // indirect
	github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869 // indirect
	github.com/bshuster-repo/logrus-logstash-hook v1.0.0 // indirect
	github.com/bugsnag/bugsnag-go v1.8.0 // indirect
	github.com/bugsnag/panicwrap v1.2.1 // indirect
	github.com/containerd/cgroups v1.0.1
	github.com/containerd/containerd v1.5.7
	github.com/containerd/typeurl v1.0.2
	github.com/cshari-zededa/eve-tpm2-tools v0.0.4
	github.com/digitalocean/go-libvirt v0.0.0-20190715144809-7b622097a793 // indirect
	github.com/digitalocean/go-qemu v0.0.0-20181112162955-dd7bb9c771b8
	github.com/docker/docker v20.10.7+incompatible
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/eriknordmark/ipinfo v0.0.0-20190220084921-7ee0839158f9
	github.com/fsnotify/fsnotify v1.4.9
	github.com/garyburd/redigo v1.6.2 // indirect
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/gofrs/uuid v3.3.0+incompatible // indirect
	github.com/golang/protobuf v1.5.2
	github.com/google/go-cmp v0.5.6
	github.com/google/go-containerregistry v0.6.0
	github.com/google/go-tpm v0.3.0
	github.com/google/gopacket v1.1.19
	github.com/gorilla/handlers v1.5.1 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/gorilla/websocket v1.4.2
	github.com/grandcat/zeroconf v1.0.0
	github.com/jackwakefield/gopac v1.0.2
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/lf-edge/edge-containers v0.0.0-20210630151415-7dbb4f290dab
	github.com/lf-edge/eve/api/go v0.0.0-00010101000000-000000000000
	github.com/lf-edge/eve/libs/zedUpload v0.0.0-20210120050122-276fea8f6efd
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/ochapman/godmi v0.0.0-20140902235245-2527e2081a16 // indirect
	github.com/onsi/gomega v1.10.3
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.1
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/packetcap/go-pcap v0.0.0-20210809221331-e2e6b14e1812
	github.com/prometheus/client_golang v1.9.0 // indirect
	github.com/prometheus/common v0.17.0 // indirect
	github.com/rackn/gohai v0.0.0-20190321191141-5053e7f1fa36
	github.com/robertkrimen/otto v0.0.0-20180617131154-15f95af6e78d // indirect
	github.com/satori/go.uuid v1.2.1-0.20180404165556-75cca531ea76
	github.com/shirou/gopsutil v0.0.0-20190323131628-2cbc9195c892
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/tatsushid/go-fastping v0.0.0-20160109021039-d7bb493dee3e
	github.com/vishvananda/netlink v1.1.1-0.20210924202909-187053b97868
	github.com/yvasiyarov/go-metrics v0.0.0-20150112132944-c25f46c4b940 // indirect
	github.com/yvasiyarov/gorelic v0.0.7 // indirect
	github.com/yvasiyarov/newrelic_platform_go v0.0.0-20160601141957-9c099fbc30e9 // indirect
	go.opencensus.io v0.23.0 // indirect
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	golang.org/x/net v0.0.0-20210805182204-aaa1db679c0d
	golang.org/x/sys v0.0.0-20210809222454-d867a43fc93e
	google.golang.org/grpc v1.38.0
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
)

replace github.com/lf-edge/eve/api/go => ../../api/go

replace github.com/lf-edge/eve/libs/zedUpload => ../../libs/zedUpload

replace git.apache.org/thrift.git => github.com/apache/thrift v0.12.0

// because containerd
replace github.com/docker/distribution => github.com/docker/distribution v0.0.0-20190205005809-0d3efadf0154
