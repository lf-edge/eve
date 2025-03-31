module github.com/lf-edge/eve/pkg/kube

go 1.24.1

require (
	github.com/containernetworking/cni v1.1.2
	github.com/containernetworking/plugins v1.3.0
	github.com/lf-edge/eve/pkg/kube/cnirpc v0.0.0-00010101000000-000000000000
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
)

require (
	github.com/coreos/go-iptables v0.6.0 // indirect
	github.com/safchain/ethtool v0.3.0 // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/vishvananda/netlink v1.2.1-beta.2 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	golang.org/x/net v0.36.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

// TODO: Remove the replace directive once cnirpc is merged.
replace github.com/lf-edge/eve/pkg/kube/cnirpc => ../cnirpc
