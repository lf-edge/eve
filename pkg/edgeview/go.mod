module github.com/edge-view

go 1.15

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
	golang.org/x/sys v0.0.0-20220722155257-8c9f86f7a55f
)
