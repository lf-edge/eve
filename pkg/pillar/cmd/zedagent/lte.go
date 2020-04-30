// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Extract LTE information from files

package zedagent

import (
	"encoding/json"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
)

const (
	infoFile     = "/run/wwan/serving-system.json"
	metricsFile  = "/run/wwan/signal-info.json"
	networksFile = "/run/wwan/networks-info.json"
)

type fileFormat map[string]interface{}

func readLTEInfo() []types.MetricItem {
	return readLTE(infoFile, "")
}

func readLTENetworks() []types.MetricItem {
	return readLTE(networksFile, "lte-networks")
}

func readLTEMetrics() []types.MetricItem {
	return readLTE(metricsFile, "")
}

func readLTE(filename string, verbatim string) []types.MetricItem {
	var items []types.MetricItem
	var m fileFormat

	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Errorf("readLTE: %s", err)
		}
		return items
	}
	if verbatim != "" {
		// Just return file content as a single string
		log.Debugf("readLTE verbatim %s: %s",
			verbatim, string(bytes))
		info := types.MetricItem{Key: verbatim, Value: string(bytes)}
		info.Type = types.MetricItemOther
		items = append(items, info)
		return items
	}
	err = json.Unmarshal(bytes, &m)
	if err != nil {
		log.Errorf("readLTE for %s: %s", filename, err)
		return items
	}
	for k, v := range m {
		info := types.MetricItem{Key: k, Value: parseAny(v)}

		// XXX Set Type to what? Guess based on type?
		// Need to have providers include the type explicitly.
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
			log.Errorf("Unknown %T from %s", t, filename)
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
		return v
	default:
		log.Errorf("parseAny unknown %T", t)
		return fmt.Sprintf("unknown type %T", t)
	}
}
