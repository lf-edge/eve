// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"strconv"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// ProcessMetric captures information for a single process
type ProcessMetric struct {
	Pid           int32
	Name          string
	UserProcess   bool
	Watched       bool // watched by watchdog
	NumFDs        int32
	NumThreads    int32
	UserTime      float64 // CPU seconds since create
	SystemTime    float64 // CPU seconds since create
	CPUPercent    float64 // UserTime and SystemTime provide time series
	CreateTime    time.Time
	VMBytes       uint64
	RssBytes      uint64
	MemoryPercent float32
	Stack         string
}

// Key returns the key for pubsub
func (metric ProcessMetric) Key() string {
	return strconv.Itoa(int(metric.Pid))
}

// LogCreate :
func (metric ProcessMetric) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.ProcessMetricLogType, "",
		nilUUID, metric.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("Process metric create")
}

// LogModify :
func (metric ProcessMetric) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.ProcessMetricLogType, "",
		nilUUID, metric.LogKey())

	oldMetric, ok := old.(ProcessMetric)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of ProcessMetric type")
	}
	// XXX remove? XXX huge?
	logObject.CloneAndAddField("diff", cmp.Diff(oldMetric, metric)).
		Metricf("Process metric modify")
}

// LogDelete :
func (metric ProcessMetric) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.ProcessMetricLogType, "",
		nilUUID, metric.LogKey())
	logObject.Metricf("Process metric delete")

	base.DeleteLogObject(logBase, metric.LogKey())
}

// LogKey :
func (metric ProcessMetric) LogKey() string {
	return string(base.ProcessMetricLogType) + "-" + metric.Key()
}
