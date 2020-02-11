module github.com/lf-edge/eve/pkg/lisp

go 1.12

require (
	contrib.go.opencensus.io/exporter/ocagent v0.4.11 // indirect
	github.com/Azure/go-autorest v13.0.1+incompatible // indirect
	github.com/google/gopacket v1.1.16
	github.com/lf-edge/eve/pkg/pillar v0.0.0-20200211160554-32163b631888
	github.com/marstr/guid v1.1.0 // indirect
	github.com/sirupsen/logrus v1.4.2
	golang.org/x/net v0.0.0-20191004110552-13f9640d40b9
)

replace github.com/lf-edge/eve/api/go => ../../api/go

// replace github.com/lf-edge/eve/pkg/pillar => ../../../../../pkg/pillar

replace github.com/vishvananda/netlink/nl => github.com/eriknordmark/netlink/nl v0.0.0-20190903203740-41fa442996b8

replace github.com/vishvananda/netlink => github.com/eriknordmark/netlink v0.0.0-20190903203740-41fa442996b8

replace git.apache.org/thrift.git => github.com/apache/thrift v0.12.0
