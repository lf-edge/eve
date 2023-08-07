module github.com/lf-edge/eve/pkg/edgeview

go 1.20

replace github.com/lf-edge/eve/libs/depgraph => github.com/lf-edge/eve/libs/depgraph v0.0.0-20220629080033-b2471c507920

require (
	github.com/gorilla/websocket v1.4.2
	github.com/grandcat/zeroconf v1.0.0
	github.com/lf-edge/eve/api/go v0.0.0-20230602070228-0c11e32c7718
	github.com/lf-edge/eve/pkg/pillar v0.0.0-20230711061722-c5e34759d661
	github.com/satori/go.uuid v1.2.1-0.20180404165556-75cca531ea76
	github.com/shirou/gopsutil v3.21.11+incompatible
	github.com/sirupsen/logrus v1.9.0
	github.com/tatsushid/go-fastping v0.0.0-20160109021039-d7bb493dee3e
	github.com/vishvananda/netlink v1.1.1-0.20210924202909-187053b97868
	golang.org/x/sys v0.5.0
)

require (
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/eriknordmark/ipinfo v0.0.0-20190220084921-7ee0839158f9 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/go-containerregistry v0.8.0 // indirect
	github.com/miekg/dns v1.1.41 // indirect
	github.com/tklauser/go-sysconf v0.3.11 // indirect
	github.com/tklauser/numcpus v0.6.0 // indirect
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	golang.org/x/net v0.7.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
)
