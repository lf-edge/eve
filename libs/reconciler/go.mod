module github.com/lf-edge/eve/libs/reconciler

go 1.20

replace github.com/lf-edge/eve/libs/depgraph => ../depgraph

require (
	github.com/lf-edge/eve/libs/depgraph v0.0.0-00010101000000-000000000000
	github.com/onsi/gomega v1.10.3 // indirect
)
