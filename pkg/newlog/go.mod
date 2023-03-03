module github.com/lf-edge/eve/pkg/newlog

go 1.20

require (
	github.com/euank/go-kmsg-parser v2.0.0+incompatible
	github.com/golang/protobuf v1.5.2
	github.com/google/go-cmp v0.5.9
	github.com/lf-edge/eve/api/go v0.0.0-20220616105859-8b9463e1561b
	github.com/lf-edge/eve/pkg/pillar v0.0.0-20230303013136-e890ce9ee8a3
	github.com/sirupsen/logrus v1.9.0
)

require (
	github.com/eriknordmark/ipinfo v0.0.0-20190220084921-7ee0839158f9 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/go-containerregistry v0.8.0 // indirect
	github.com/satori/go.uuid v1.2.1-0.20180404165556-75cca531ea76 // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/vishvananda/netlink v1.1.1-0.20210924202909-187053b97868 // indirect
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	golang.org/x/sys v0.5.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
)

replace github.com/lf-edge/eve/api/go => ../../api/go
