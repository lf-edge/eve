// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/cmd/baseosmgr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/client"
	"github.com/lf-edge/eve/pkg/pillar/cmd/conntrack"
	"github.com/lf-edge/eve/pkg/pillar/cmd/diag"
	"github.com/lf-edge/eve/pkg/pillar/cmd/domainmgr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/downloader"
	"github.com/lf-edge/eve/pkg/pillar/cmd/hardwaremodel"
	"github.com/lf-edge/eve/pkg/pillar/cmd/identitymgr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/ipcmonitor"
	"github.com/lf-edge/eve/pkg/pillar/cmd/ledmanager"
	"github.com/lf-edge/eve/pkg/pillar/cmd/logmanager"
	"github.com/lf-edge/eve/pkg/pillar/cmd/nim"
	"github.com/lf-edge/eve/pkg/pillar/cmd/nodeagent"
	"github.com/lf-edge/eve/pkg/pillar/cmd/tpmmgr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/vaultmgr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/verifier"
	"github.com/lf-edge/eve/pkg/pillar/cmd/waitforaddr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/wstunnelclient"
	"github.com/lf-edge/eve/pkg/pillar/cmd/zedagent"
	"github.com/lf-edge/eve/pkg/pillar/cmd/zedmanager"
	"github.com/lf-edge/eve/pkg/pillar/cmd/zedrouter"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"os"
	"path/filepath"
)

func main() {
	ps := pubsub.New(&socketdriver.SocketDriver{})

	basename := filepath.Base(os.Args[0])
	switch basename {
	case "client":
		client.Run(ps)
	case "diag":
		diag.Run(ps)
	case "domainmgr":
		domainmgr.Run(ps)
	case "downloader":
		downloader.Run(ps)
	case "hardwaremodel":
		hardwaremodel.Run(ps)
	case "identitymgr":
		identitymgr.Run(ps)
	case "ledmanager":
		ledmanager.Run(ps)
	case "logmanager":
		logmanager.Run(ps)
	case "nim":
		nim.Run(ps)
	case "nodeagent":
		nodeagent.Run(ps)
	case "verifier":
		verifier.Run(ps)
	case "waitforaddr":
		waitforaddr.Run(ps)
	case "zedagent":
		zedagent.Run(ps)
	case "zedmanager":
		zedmanager.Run(ps)
	case "zedrouter":
		zedrouter.Run(ps)
	case "ipcmonitor":
		ipcmonitor.Run(ps)
	case "baseosmgr":
		baseosmgr.Run(ps)
	case "wstunnelclient":
		wstunnelclient.Run(ps)
	case "conntrack":
		conntrack.Run(ps)
	case "tpmmgr":
		tpmmgr.Run(ps)
	case "vaultmgr":
		vaultmgr.Run(ps)
	default:
		fmt.Printf("Unknown package: %s\n", basename)
	}
}
