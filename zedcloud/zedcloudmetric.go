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
	RecvByteCount int64 // Based on content-length which could be off
}

// Key is ifname string
type metricsMap map[string]zedcloudMetric

var metrics metricsMap = make(metricsMap)

func maybeInit(ifname string) {
	if metrics == nil {
		log.Fatal("no zedcloudmetric map\n")
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

// Concatenate different interfaces and URLs into a union map
func Append(cms metricsMap, cms1 metricsMap) metricsMap {
	for ifname, cm1 := range cms1 {
		cm, ok := cms[ifname]
		if !ok {
			// New ifname; take all
			cms[ifname] = cm
			continue
		}
		if cm.LastFailure.IsZero() {
			// Don't care if cm1 is zero
			cm.LastFailure = cm1.LastFailure
		} else if !cm1.LastFailure.IsZero() &&
			cm1.LastFailure.Sub(cm.LastFailure) > 0 {
			cm.LastFailure = cm1.LastFailure
		}
		if cm.LastSuccess.IsZero() {
			// Don't care if cm1 is zero
			cm.LastSuccess = cm1.LastSuccess
		} else if !cm1.LastSuccess.IsZero() &&
			cm1.LastSuccess.Sub(cm.LastSuccess) > 0 {
			cm.LastSuccess = cm1.LastSuccess
		}
		cm.FailureCount += cm1.FailureCount
		cm.SuccessCount += cm1.SuccessCount
		for url, um1 := range cm1.UrlCounters {
			cmu := cm.UrlCounters // A pointer to the map
			um, ok := cmu[url]
			if !ok {
				// New url; take all
				cmu[url] = um1
				continue
			}
			um.TryMsgCount += um1.TryMsgCount
			um.TryMsgCount += um1.TryMsgCount
			um.TryByteCount += um1.TryByteCount
			um.SentMsgCount += um1.SentMsgCount
			um.SentByteCount += um1.SentByteCount
			um.RecvMsgCount += um1.RecvMsgCount
			um.RecvByteCount += um1.RecvByteCount
			cmu[url] = um
		}
		cms[ifname] = cm
	}
	return cms
}
