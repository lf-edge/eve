// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/lf-edge/eve/pkg/pillar/cmd/baseosmgr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/client"
	"github.com/lf-edge/eve/pkg/pillar/cmd/command"
	"github.com/lf-edge/eve/pkg/pillar/cmd/conntrack"
	"github.com/lf-edge/eve/pkg/pillar/cmd/diag"
	"github.com/lf-edge/eve/pkg/pillar/cmd/domainmgr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/downloader"
	"github.com/lf-edge/eve/pkg/pillar/cmd/executor"
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
)

var entrypoints = map[string]func(*pubsub.PubSub){
	"client":         client.Run,
	"command":        command.Run,
	"diag":           diag.Run,
	"domainmgr":      domainmgr.Run,
	"downloader":     downloader.Run,
	"executor":       executor.Run,
	"hardwaremodel":  hardwaremodel.Run,
	"identitymgr":    identitymgr.Run,
	"ledmanager":     ledmanager.Run,
	"logmanager":     logmanager.Run,
	"nim":            nim.Run,
	"nodeagent":      nodeagent.Run,
	"verifier":       verifier.Run,
	"waitforaddr":    waitforaddr.Run,
	"zedagent":       zedagent.Run,
	"zedmanager":     zedmanager.Run,
	"zedrouter":      zedrouter.Run,
	"ipcmonitor":     ipcmonitor.Run,
	"baseosmgr":      baseosmgr.Run,
	"wstunnelclient": wstunnelclient.Run,
	"conntrack":      conntrack.Run,
	"tpmmgr":         tpmmgr.Run,
	"vaultmgr":       vaultmgr.Run,
}

func main() {
	ps := pubsub.New(&socketdriver.SocketDriver{})

	basename := filepath.Base(os.Args[0])
	if entrypoint, ok := entrypoints[basename]; ok {
		entrypoint(ps)
	} else {
		fmt.Printf("Unknown package: %s\n", basename)
		os.Exit(1)
	}
}
