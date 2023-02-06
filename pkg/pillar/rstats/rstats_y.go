//go:build rstats
// +build rstats

package rstats

import (
	"fmt"

	"github.com/shjala/gostats"
)

// Endpoint is statsd endpoint address, gets replaced at build time.
var Endpoint = "<ip>:<port>"

// Tag is bucket tag, gets replaced at build time.
var Tag = "<tag>"

func init() {
	// collect stats every 5 seconds
	err := gostats.Collect(Endpoint, Tag, 5, true, true, true)
	if err != nil {
		fmt.Printf("Failed to start collecting runtime stats : %v\n", err)
		return
	}
}
