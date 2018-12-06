// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package main

import (
	"fmt"
	"github.com/zededa/go-provision/cmd/client"
	"github.com/zededa/go-provision/cmd/domainmgr"
	"github.com/zededa/go-provision/cmd/downloader"
	"github.com/zededa/go-provision/cmd/hardwaremodel"
	"github.com/zededa/go-provision/cmd/identitymgr"
	"github.com/zededa/go-provision/cmd/ipcmonitor"
	"github.com/zededa/go-provision/cmd/ledmanager"
	"github.com/zededa/go-provision/cmd/logmanager"
	"github.com/zededa/go-provision/cmd/verifier"
	"github.com/zededa/go-provision/cmd/zedagent"
	"github.com/zededa/go-provision/cmd/zedmanager"
	"github.com/zededa/go-provision/cmd/zedrouter"
	"github.com/zededa/go-provision/cmd/baseosmgr"
	"os"
	"path/filepath"
)

func main() {
	basename := filepath.Base(os.Args[0])
	switch basename {
	case "client":
		client.Run()
	case "domainmgr":
		domainmgr.Run()
	case "downloader":
		downloader.Run()
	case "hardwaremodel":
		hardwaremodel.Run()
	case "identitymgr":
		identitymgr.Run()
	case "ledmanager":
		ledmanager.Run()
	case "logmanager":
		logmanager.Run()
	case "verifier":
		verifier.Run()
	case "zedagent":
		zedagent.Run()
	case "zedmanager":
		zedmanager.Run()
	case "zedrouter":
		zedrouter.Run()
	case "ipcmonitor":
		ipcmonitor.Run()
	case "baseosmgr":
		baseosmgr.Run()
	default:
		fmt.Printf("Unknown package: %s\n", basename)
	}
}
