//go:build !rstats
// +build !rstats

package rstats

// Endpoint is statsd endpoint address, gets replaced at build time.
var Endpoint = "<ip>:<port>"

// Tag is bucket tag, gets replaced at build time.
var Tag = "<tag>"
