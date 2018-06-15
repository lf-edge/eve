// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package zedrouter

import (
	"encoding/json"
	"github.com/zededa/go-provision/types"
	"log"
)

// XXX move to library? template?
// XXX alternative seems to be a deep copy of some sort

func CastNetworkObjectConfig(in interface{}) types.NetworkObjectConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastNetworkObjectConfig")
	}
	var output types.NetworkObjectConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastNetworkObjectConfig")
	}
	return output
}

func CastNetworkObjectStatus(in interface{}) types.NetworkObjectStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastNetworkObjectStatus")
	}
	var output types.NetworkObjectStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastNetworkObjectStatus")
	}
	return output
}

func CastNetworkServiceConfig(in interface{}) types.NetworkServiceConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastNetworkServiceConfig")
	}
	var output types.NetworkServiceConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastNetworkServiceConfig")
	}
	return output
}

func CastNetworkServiceStatus(in interface{}) types.NetworkServiceStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastNetworkServiceStatus")
	}
	var output types.NetworkServiceStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastNetworkServiceStatus")
	}
	return output
}
