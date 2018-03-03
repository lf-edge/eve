// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Extract LTE information from files

package main

import (
	"encoding/json"
	"fmt"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"log"
	"strconv"
)

const (
	infoFile    = "/run/wwan/serving-system.json"
	metricsFile = "/run/wwan/signal-info.json"
)

type fileFormat map[string]string

func readLTEInfo() []types.MetricItem {
	return readLTE(infoFile)
}

func readLTEMetrics() []types.MetricItem {
	return readLTE(metricsFile)
}

func readLTE(filename string) []types.MetricItem {
	var items []types.MetricItem
	var m fileFormat

	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Printf("readLTE: %s\n", err)
		return items
	}
	err = json.Unmarshal(bytes, &m)
	if err != nil {
		log.Printf("readLTE for %s: %s\n", filename, err)
		return items
	}
	for k, v := range m {
		info := types.MetricItem{Key: k, Value: parseAny(v)}

		// XXX remove
		// fmt.Printf("Got %s %v type %T\n", k, info.Value, info.Value)
		// XXX Set Type to what? Guess based on type?
		switch t := info.Value.(type) {
		case uint64:
			info.Type = types.MetricItemCounter
		case uint32:
			info.Type = types.MetricItemCounter
		case bool:
			info.Type = types.MetricItemState
		case float32:
			info.Type = types.MetricItemGauge
		case string:
			info.Type = types.MetricItemOther
		default:
			log.Printf("Unknown %T from %s\n", t, filename)
		}

		items = append(items, info)
	}
	return items
}

// Note that any negative number is returned as a float
func parseAny(v string) interface{} {
	b, err := strconv.ParseBool(v)
	if err == nil {
		return b
	}
	u, err := strconv.ParseUint(v, 10, 32)
	if err == nil {
		return uint32(u)
	}
	u, err = strconv.ParseUint(v, 10, 64)
	if err == nil {
		return u
	}
	f, err := strconv.ParseFloat(v, 32)
	if err == nil {
		return float32(f)
	}
	// Must be string
	return v
}

// XXX remove
func XXXmain() {
	res := readLTEInfo()
	fmt.Printf("Info %v\n", res)
	res = readLTEMetrics()
	fmt.Printf("Metrics %v\n", res)
}
