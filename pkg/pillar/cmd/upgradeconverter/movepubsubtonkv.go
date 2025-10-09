// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"path/filepath"

	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

// we cannot copy all /persist/status to /persist/nkv-storage,
// there are files, which are not pubsub topics, yet they are
// saved under /persist/status, so we
//
// alternative: copy all folders from /persist/status?
func movePersistPubsubToNkv(ctxPtr *ucContext) error {
	agentFolders := []string{
		"newlogd",
		"zfsmanager",
		"monitor",
		"diag",
		"nim",
		"watcher",
		"usbmanager",
		"upgradeconverter",
		"conntrack",
		"faultinjection",
		"ledmanager",
		"nodeagent",
		"tpmmgr",
		"downloader",
		"vaultmgr",
		"hardwaremodel",
		"volumemgr",
		"waitforaddr",
		"zedkube",
		"baseosmgr",
		"verifier",
		"executor",
		"zedagent",
		"domainmgr",
		"command",
		"ipcmonitor",
		"wstunnelclient",
		"zedrouter",
		"zedclient",
		"loguploader",
		"pbuf",
		"zedmanager",
		"collectinfo",
		"zedbox",
		"edgeview",
		"installer",
		"wwan",
	}

	// current nkv implementation uses digest folder to store processed
	// topics
	for _, agent := range agentFolders {
		src := filepath.Join(ctxPtr.persistStatusDir, agent)
		dst := filepath.Join(ctxPtr.persistDir, "nkv-storage", "digest", agent)
		srcExists := fileutils.DirExists(log, src)
		dstExists := fileutils.DirExists(log, dst)

		if srcExists && !dstExists {
			if err := fileutils.CopyDir(src, dst); err != nil {
				return err
			}
		}

	}

	return nil
}
