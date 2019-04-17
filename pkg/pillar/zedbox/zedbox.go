// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"github.com/zededa/eve/pkg/pillar/cmd/baseosmgr"
	"github.com/zededa/eve/pkg/pillar/cmd/client"
	"github.com/zededa/eve/pkg/pillar/cmd/conntrack"
	"github.com/zededa/eve/pkg/pillar/cmd/dataplane"
	"github.com/zededa/eve/pkg/pillar/cmd/diag"
	"github.com/zededa/eve/pkg/pillar/cmd/domainmgr"
	"github.com/zededa/eve/pkg/pillar/cmd/downloader"
	"github.com/zededa/eve/pkg/pillar/cmd/hardwaremodel"
	"github.com/zededa/eve/pkg/pillar/cmd/identitymgr"
	"github.com/zededa/eve/pkg/pillar/cmd/ipcmonitor"
	"github.com/zededa/eve/pkg/pillar/cmd/ledmanager"
	"github.com/zededa/eve/pkg/pillar/cmd/logmanager"
	"github.com/zededa/eve/pkg/pillar/cmd/nim"
	"github.com/zededa/eve/pkg/pillar/cmd/verifier"
	"github.com/zededa/eve/pkg/pillar/cmd/waitforaddr"
	"github.com/zededa/eve/pkg/pillar/cmd/wstunnelclient"
	"github.com/zededa/eve/pkg/pillar/cmd/zedagent"
	"github.com/zededa/eve/pkg/pillar/cmd/zedmanager"
	"github.com/zededa/eve/pkg/pillar/cmd/zedrouter"
	"os"
	"path/filepath"
)

func main() {
	basename := filepath.Base(os.Args[0])
	switch basename {
	case "client":
		client.Run()
	case "diag":
		diag.Run()
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
	case "lisp-ztr":
		dataplane.Run()
	case "logmanager":
		logmanager.Run()
	case "nim":
		nim.Run()
	case "verifier":
		verifier.Run()
	case "waitforaddr":
		waitforaddr.Run()
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
	case "wstunnelclient":
		wstunnelclient.Run()
	case "conntrack":
		conntrack.Run()
	default:
		fmt.Printf("Unknown package: %s\n", basename)
	}
}
