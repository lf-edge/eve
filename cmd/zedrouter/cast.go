// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle NetworkService setup

package zedrouter

import (
	"encoding/json"
	"github.com/zededa/go-provision/types"
	"log"
)

// XXX move to library? template?
// XXX alternative seems to be a deep copy of some sort
func CastNetworkConfig(in interface{}) types.NetworkConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastNetworkConfig")
	}
	var output types.NetworkConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastNetworkConfig")
	}
	return output
}

func CastNetworkService(in interface{}) types.NetworkService {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastNetworkService")
	}
	var output types.NetworkService
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastNetworkService")
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
