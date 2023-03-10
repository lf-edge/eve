module github.com/lf-edge/eve/pkg/edgeview

go 1.20

replace github.com/lf-edge/eve/api/go => github.com/lf-edge/eve/api/go v0.0.0-20220822214905-7a5b0a24ad8f

replace github.com/lf-edge/eve/libs/depgraph => github.com/lf-edge/eve/libs/depgraph v0.0.0-20220629080033-b2471c507920

require (
	github.com/gorilla/websocket v1.4.2
	github.com/grandcat/zeroconf v1.0.0
	github.com/lf-edge/eve/api/go v0.0.0-20220629080033-b2471c507920
	github.com/lf-edge/eve/pkg/pillar v0.0.0-20221025082440-d8005e30e22d
	github.com/satori/go.uuid v1.2.1-0.20180404165556-75cca531ea76
	github.com/shirou/gopsutil v0.0.0-20190901111213-e4ec7b275ada
	github.com/sirupsen/logrus v1.8.1
	github.com/tatsushid/go-fastping v0.0.0-20160109021039-d7bb493dee3e
	github.com/vishvananda/netlink v1.1.1-0.20210924202909-187053b97868
	golang.org/x/sys v0.5.0
)

require (
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/eriknordmark/ipinfo v0.0.0-20190220084921-7ee0839158f9 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/google/go-cmp v0.5.7 // indirect
	github.com/google/go-containerregistry v0.8.0 // indirect
	github.com/miekg/dns v1.1.41 // indirect
	github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4 // indirect
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f // indirect
	golang.org/x/net v0.7.0 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)
