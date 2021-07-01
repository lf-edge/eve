module github.com/lf-edge/eve/pkg/newlog

go 1.15

require (
	github.com/euank/go-kmsg-parser v2.0.0+incompatible
	github.com/golang/protobuf v1.4.3
	github.com/google/go-cmp v0.5.4
	github.com/lf-edge/eve/api/go v0.0.0-00010101000000-000000000000
	github.com/lf-edge/eve/pkg/pillar v0.0.0-20200211160554-32163b631888
	github.com/sirupsen/logrus v1.8.1
)

replace github.com/lf-edge/eve/api/go => ../../api/go

replace github.com/lf-edge/eve/pkg/pillar => ../pillar

replace github.com/vishvananda/netlink/nl => github.com/eriknordmark/netlink/nl v0.0.0-20190903203740-41fa442996b8

replace github.com/vishvananda/netlink => github.com/eriknordmark/netlink v0.0.0-20190903203740-41fa442996b8
