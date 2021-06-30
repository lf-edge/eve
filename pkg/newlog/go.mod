module github.com/lf-edge/eve/pkg/newlog

go 1.15

require (
	github.com/euank/go-kmsg-parser v2.0.0+incompatible
	github.com/golang/protobuf v1.4.3
	github.com/google/go-cmp v0.5.4
	github.com/lf-edge/eve/api/go v0.0.0-00010101000000-000000000000
	github.com/lf-edge/eve/pkg/pillar v0.0.0-20210526054436-4dcc82533ea3
	github.com/sirupsen/logrus v1.8.1
)

replace github.com/lf-edge/eve/api/go => ../../api/go

replace github.com/lf-edge/eve/pkg/pillar => ../pillar

replace github.com/vishvananda/netlink => github.com/eriknordmark/netlink v0.0.0-20210521210133-6f4f9eb80eb3
