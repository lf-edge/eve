module github.com/lf-edge/eve/evetest/testapps/lps

go 1.25.0

toolchain go1.25.11

require (
	github.com/lf-edge/eve-api/go v0.0.0-20260622100545-186e61c68f39
	google.golang.org/protobuf v1.36.11
)

replace github.com/lf-edge/eve-api/go => github.com/milan-zededa/eve-api/go v0.0.0-20260423135209-3859c9c5393a
