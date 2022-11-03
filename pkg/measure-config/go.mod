module github.com/measure-config

go 1.15

replace github.com/lf-edge/eve/api/go => github.com/lf-edge/eve/api/go v0.0.0-20221108162354-969f3cba94d8

replace github.com/lf-edge/eve/libs/depgraph => github.com/lf-edge/eve/libs/depgraph v0.0.0-20221108162354-969f3cba94d8

require (
	github.com/google/go-tpm v0.3.3
	github.com/lf-edge/eve/pkg/pillar v0.0.0-20221108162354-969f3cba94d8
)
