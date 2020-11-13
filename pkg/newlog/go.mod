module github.com/lf-edge/eve/pkg/newlog

go 1.12

require (
	github.com/euank/go-kmsg-parser v2.0.0+incompatible
	github.com/go-logfmt/logfmt v0.4.0 // indirect
	github.com/golang/protobuf v1.4.3
	github.com/google/go-cmp v0.5.0
	github.com/lf-edge/eve/api/go v0.0.0-00010101000000-000000000000
	github.com/lf-edge/eve/pkg/pillar v0.0.0-20200211160554-32163b631888
	github.com/sirupsen/logrus v1.7.0
	honnef.co/go/tools v0.0.0-20190523083050-ea95bdfd59fc // indirect
)

replace github.com/lf-edge/eve/api/go => ../../api/go

replace github.com/lf-edge/eve/pkg/pillar => ../pillar
