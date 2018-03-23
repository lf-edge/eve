// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Functions to maintain metrics about the connectivity to zedcloud.
// Just success and failures.
// Reported as device metrics

package main

import (
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
var metrics map[string]zedcloudMetric

func maybeInit(ifname string) {
	if metrics == nil {
		log.Printf("create zedcloudmetric map\n")
		metrics = make(map[string]zedcloudMetric)
	}
	if _, ok := metrics[ifname]; !ok {
		log.Printf("create zedcloudmetric for %s\n", ifname)
		metrics[ifname] = zedcloudMetric{
			UrlCounters: make(map[string]urlcloudMetrics),
		}
	}
}

func zedCloudFailure(ifname string, url string, reqLen int64, respLen int64) {
	maybeInit(ifname)
	m := metrics[ifname]
	m.FailureCount += 1
	m.LastFailure = time.Now()
	var u urlcloudMetrics
	var ok bool
	if u, ok = m.UrlCounters[url]; !ok {
		u = urlcloudMetrics{}
		m.UrlCounters[url] = u
	}
	u.TryMsgCount += 1
	u.TryByteCount += reqLen
	if respLen != 0 {
		u.RecvMsgCount += 1
		u.RecvByteCount += respLen
	}
	metrics[ifname] = m
}

func zedCloudSuccess(ifname string, url string, reqLen int64, respLen int64) {
	maybeInit(ifname)
	m := metrics[ifname]
	m.SuccessCount += 1
	m.LastSuccess = time.Now()
	var u urlcloudMetrics
	var ok bool
	if u, ok = m.UrlCounters[url]; !ok {
		u = urlcloudMetrics{}
		m.UrlCounters[url] = u
	}
	u.SentMsgCount += 1
	u.SentByteCount += reqLen
	u.RecvMsgCount += 1
	u.RecvByteCount += respLen
	metrics[ifname] = m
}

func getCloudMetrics() map[string]zedcloudMetric {
	return metrics
}
