// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Functions to maintain metrics about the connectivity to zedcloud.
// Just success and failures.
// Reported as device metrics

package zedcloud

import (
	"encoding/json"
	"log"
	"time"
)

type zedcloudMetric struct {
	FailureCount uint64
	SuccessCount uint64
	LastFailure  time.Time
	LastSuccess  time.Time
	UrlCounters  map[string]urlcloudMetrics
}

type urlcloudMetrics struct {
	TryMsgCount   int64
	TryByteCount  int64
	SentMsgCount  int64
	SentByteCount int64
	RecvMsgCount  int64
	RecvByteCount int64
}

// Key is ifname string
type metricsMap map[string]zedcloudMetric

var metrics metricsMap

func maybeInit(ifname string) {
	if metrics == nil {
		log.Printf("create zedcloudmetric map\n")
		metrics = make(metricsMap)
	}
	if _, ok := metrics[ifname]; !ok {
		log.Printf("create zedcloudmetric for %s\n", ifname)
		metrics[ifname] = zedcloudMetric{
			UrlCounters: make(map[string]urlcloudMetrics),
		}
	}
}

func ZedCloudFailure(ifname string, url string, reqLen int64, respLen int64) {
	maybeInit(ifname)
	m := metrics[ifname]
	m.FailureCount += 1
	m.LastFailure = time.Now()
	var u urlcloudMetrics
	var ok bool
	if u, ok = m.UrlCounters[url]; !ok {
		u = urlcloudMetrics{}
	}
	u.TryMsgCount += 1
	u.TryByteCount += reqLen
	if respLen != 0 {
		u.RecvMsgCount += 1
		u.RecvByteCount += respLen
	}
	m.UrlCounters[url] = u
	metrics[ifname] = m
}

func ZedCloudSuccess(ifname string, url string, reqLen int64, respLen int64) {
	maybeInit(ifname)
	m := metrics[ifname]
	m.SuccessCount += 1
	m.LastSuccess = time.Now()
	var u urlcloudMetrics
	var ok bool
	if u, ok = m.UrlCounters[url]; !ok {
		u = urlcloudMetrics{}
	}
	u.SentMsgCount += 1
	u.SentByteCount += reqLen
	u.RecvMsgCount += 1
	u.RecvByteCount += respLen
	m.UrlCounters[url] = u
	metrics[ifname] = m
}

func GetCloudMetrics() metricsMap {
	return metrics
}

// XXX this works but ugly as ...
// Alternative seems to be a deep walk with type assertions in order
// to produce the map of map of map with the correct type.
func CastCloudMetrics(in interface{}) metricsMap {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastCloudMetrics")
	}
	var output metricsMap
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastCloudMetrics")
	}
	return output
}

// XXX Need to walk and do type assertions for each map member
// XXX incomplete; remove or fix
func CastCloudMetrics2(in interface{}) metricsMap {
	in1 := *(in.(*interface{}))
	in2 := in1.(map[string]interface{})
	o1 := make(metricsMap)
	for k1, e1 := range in2 {
		log.Printf("Cast: %s: %v %t\n", k1, e1, e1)
		// XXX blows up on next line; need to do a deep type assertions
		elem := e1.(zedcloudMetric)
		o1[k1] = elem
	}
	return o1
}
