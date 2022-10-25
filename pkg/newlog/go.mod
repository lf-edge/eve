module github.com/lf-edge/eve/pkg/newlog

go 1.15

require (
	github.com/euank/go-kmsg-parser v2.0.0+incompatible
	github.com/golang/protobuf v1.5.2
	github.com/google/go-cmp v0.5.7
	github.com/lf-edge/eve/api/go v0.0.0-20220616105859-8b9463e1561b
	github.com/lf-edge/eve/pkg/pillar v0.0.0-20221025082440-d8005e30e22d
	github.com/sirupsen/logrus v1.8.1
)

replace github.com/lf-edge/eve/api/go => ../../api/go

replace github.com/lf-edge/eve/pkg/pillar => ../pillar

replace github.com/lf-edge/eve/libs/reconciler => ../../libs/reconciler

replace github.com/lf-edge/eve/libs/depgraph => ../../libs/depgraph
