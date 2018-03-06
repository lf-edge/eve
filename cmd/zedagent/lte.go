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

type fileFormat map[string]interface{}

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
// We seem to get float64 for integers from the json decode. Need
// to covert them here.
func parseAny(val interface{}) interface{} {
	switch t := val.(type) {
	case uint64:
		return val.(uint64)
	case uint32:
		return val.(uint32)
	case bool:
		return val.(bool)
	case float32:
		v := val.(float32)
		switch v {
		case float32(uint32(v)):
			return uint32(v)
		case float32(uint64(v)):
			return uint64(v)
		default:
			return v
		}
	case float64:
		v := val.(float64)
		switch v {
		case float64(uint32(v)):
			return uint32(v)
		case float64(uint64(v)):
			return uint64(v)
		default:
			return float32(v)
		}
	case string:
		v := val.(string)
		// XXX don't seem to need to parse these from
		// inside quotes
		if false {
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
		}
		// Must be string
		return v
	default:
		log.Printf("parseAny unknown %T\n", t)
		return fmt.Sprintf("unknown type %T", t)
	}
}

// XXX remove
func XXXmain() {
	res := readLTEInfo()
	fmt.Printf("Info %v\n", res)
	res = readLTEMetrics()
	fmt.Printf("Metrics %v\n", res)
}
