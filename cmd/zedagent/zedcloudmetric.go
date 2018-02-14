// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Functions to maintain metrics about the connectivity to zedcloud.
// Just success and failures.
// Reported as device metrics

package main

import (
	"fmt"
	"time"
)

type zedcloudMetric struct {
	FailureCount uint64
	SuccessCount uint64
	LastFailure  time.Time
	LastSuccess  time.Time
}

// Key is ifname string
var metrics map[string]zedcloudMetric

func maybeInit(ifname string) {
	if metrics == nil {
		fmt.Printf("create zedcloudmetric map\n")
		metrics = make(map[string]zedcloudMetric)
	}
	if _, ok := metrics[ifname]; !ok {
		fmt.Printf("create zedcloudmetric for %s\n", ifname)
		metrics[ifname] = zedcloudMetric{}
	}
}

func zedCloudFailure(ifname string) {
	maybeInit(ifname)
	m := metrics[ifname]
	m.FailureCount += 1
	m.LastFailure = time.Now()
	metrics[ifname] = m
}

func zedCloudSuccess(ifname string) {
	maybeInit(ifname)
	m := metrics[ifname]
	m.SuccessCount += 1
	m.LastSuccess = time.Now()
	metrics[ifname] = m
}

func getCloudMetrics() map[string]zedcloudMetric {
	return metrics
}
