module github.com/lf-edge/eve/pkg/wwan/mmagent

go 1.20

require (
	github.com/godbus/dbus/v5 v5.1.0
	github.com/lf-edge/eve/pkg/pillar v0.0.0-20230822182336-ed4fe09560c6
	github.com/miekg/dns v1.1.55
	github.com/sirupsen/logrus v1.9.0
	github.com/tatsushid/go-fastping v0.0.0-20160109021039-d7bb493dee3e
	github.com/vishvananda/netlink v1.1.1-0.20210924202909-187053b97868
	golang.org/x/sys v0.5.0
)

// Note that this replace is temporary and will be removed once the ModemManager PR
// is merged and we can therefore point mmagent to the upstream version of pillar
// with all the changes that it needs.
replace github.com/lf-edge/eve/pkg/pillar => ../../pillar

require (
	github.com/eriknordmark/ipinfo v0.0.0-20230728132417-2d8f4da903d7 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/go-containerregistry v0.8.0 // indirect
	github.com/google/go-tpm v0.3.0 // indirect
	github.com/lf-edge/eve-api/go v0.0.0-20230818142341-272fc065f4cb // indirect
	github.com/satori/go.uuid v1.2.1-0.20180404165556-75cca531ea76 // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	golang.org/x/mod v0.7.0 // indirect
	golang.org/x/net v0.7.0 // indirect
	golang.org/x/tools v0.3.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
)
