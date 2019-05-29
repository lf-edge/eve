package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/rackn/gohai/plugins/dmi"
	"github.com/rackn/gohai/plugins/net"
	"github.com/rackn/gohai/plugins/storage"
	"github.com/rackn/gohai/plugins/system"
)

type info interface {
	Class() string
}

func main() {
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

        out := os.Stdout
        if len(os.Args) > 1 {
                out, err = os.Create(os.Args[1])
                if err != nil {
                        log.Fatalf("Failed to created an output file: %v", err)
                }
        }

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	enc.Encode(infos)
}
