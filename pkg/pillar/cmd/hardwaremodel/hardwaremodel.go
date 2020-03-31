// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardwaremodel

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/rackn/gohai/plugins/dmi"
	"github.com/rackn/gohai/plugins/net"
	"github.com/rackn/gohai/plugins/storage"
	"github.com/rackn/gohai/plugins/system"
)

type info interface {
	Class() string
}

func hwFp() {
	infos := map[string]info{}
	dmiInfo, err := dmi.Gather()
	if err != nil {
		log.Fatalf("Failed to gather DMI information: %v", err)
	}
	infos[dmiInfo.Class()] = dmiInfo
	netInfo, err := net.Gather()
	if err != nil {
		log.Fatalf("Failed to gather network info: %v", err)
	}
	infos[netInfo.Class()] = netInfo
	sysInfo, err := system.Gather()
	if err != nil {
		log.Fatalf("Failed to gather basic OS info: %v", err)
	}
	infos[sysInfo.Class()] = sysInfo
	storInfo, err := storage.Gather()
	if err != nil {
		log.Fatalf("Failed to gather storage info: %v", err)
	}
	infos[storInfo.Class()] = storInfo

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(infos)
}

func Run(ps *pubsub.PubSub) {
	cPtr := flag.Bool("c", false, "No CRLF")
	hwPtr := flag.Bool("f", false, "Fingerprint hardware")
	flag.Parse()
	if *hwPtr {
		hwFp()
		return
	}
	model := hardware.GetHardwareModelNoOverride()
	if *cPtr {
		fmt.Printf("%s", model)
	} else {
		fmt.Printf("%s\n", model)
	}
}
