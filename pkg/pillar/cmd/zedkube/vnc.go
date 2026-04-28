// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kubevirt.io/client-go/kubecli"
)

// runAppVNC - run vnc for EVE 'k' VMI remote console
func (z *zedkube) runAppVNC(config *types.AppInstanceConfig) {
	log.Noticef("runAppVNC: starting for app %s, RemoteConsole=%v",
		config.DisplayName, config.RemoteConsole)

	vmconfig := config.FixedResources

	var vmiName string
	for i := 5; i >= 0; i-- {
		var err error
		vmiName, err = z.getVMIdomainName(config)
		if err != nil {
			log.Noticef("runAppVNC: get vmi domainname error %v, retries left %d", err, i)
			time.Sleep(3 * time.Second)
			continue
		}
		break
	}
	if vmiName == "" {
		log.Errorf("runAppVNC: can not find vmiName for app %s", config.DisplayName)
		return
	}
	log.Noticef("runAppVNC: found vmiName %s for app %s", vmiName, config.DisplayName)

	vncPort := vmconfig.VncDisplay + 5900

	appUUID := config.UUIDandVersion.UUID.String()
	if config.RemoteConsole {
		// Block only on an active session; reclaim the file otherwise.
		if !canClaimVNCFile(appUUID) {
			return
		}

		// Ensure the VNC directory exists
		if err := os.MkdirAll(types.VmiVNCDir, 0755); err != nil {
			log.Errorf("runAppVNC: Error creating VNC directory %s: %v", types.VmiVNCDir, err)
			return
		}

		// Write JSON format config file
		vncConfig := types.VmiVNCConfig{
			VMIName: vmiName,
			VNCPort: uint32(vncPort),
			AppUUID: appUUID,
			// CallerPID is not set for remote-console VNC (only edgeview sets it)
		}

		content, err := json.Marshal(vncConfig)
		if err != nil {
			log.Errorf("runAppVNC: Error marshaling VNC config: %v", err)
			return
		}

		err = os.WriteFile(types.VmiVNCFileName, content, 0644)
		if err != nil {
			log.Errorf("runAppVNC: Error creating file %s: %v", types.VmiVNCFileName, err)
			return
		}
		log.Noticef("runAppVNC: vmiName %s, port %d, vmiVNC file %s created",
			vmiName, vncPort, types.VmiVNCFileName)
	} else {
		if _, err := os.Stat(types.VmiVNCFileName); err == nil {
			log.Noticef("runAppVNC: RemoteConsole disabled, removing VNC file %s", types.VmiVNCFileName)
			err = os.Remove(types.VmiVNCFileName)
			if err != nil {
				log.Errorf("runAppVNC: Error remove file %v", err)
				return
			}
		}
	}
	log.Noticef("runAppVNC: %s done", vmiName)
}

// canClaimVNCFile returns true if the current vmiVNC.run (if any) is safe to
// overwrite for remote-console of appUUID. It blocks only on a session that is
// currently live: an active edgeview instance, or a different app's
// remote-console whose virtctl proxy is still listening. A stale file from a
// dead edgeview or an earlier zedkube incarnation is removed so the caller can
// proceed.
func canClaimVNCFile(appUUID string) bool {
	data, err := os.ReadFile(types.VmiVNCFileName)
	if err != nil {
		return true // absent or unreadable via Stat path upstream
	}
	var existing types.VmiVNCConfig
	if err := json.Unmarshal(data, &existing); err != nil || existing.VNCPort == 0 {
		log.Noticef("canClaimVNCFile: unreadable VNC file, removing")
		os.Remove(types.VmiVNCFileName)
		return true
	}
	if existing.CallerPID > 0 {
		if existing.OwnerAlive() {
			log.Errorf("canClaimVNCFile: active edgeview VNC session (pid %d), cannot start remote-console",
				existing.CallerPID)
			return false
		}
		log.Noticef("canClaimVNCFile: removing stale edgeview VNC file (pid %d dead or reused)",
			existing.CallerPID)
		os.Remove(types.VmiVNCFileName)
		return true
	}
	// CallerPID unset: zedkube-owned remote-console file.
	if existing.AppUUID == appUUID {
		log.Noticef("canClaimVNCFile: reclaiming own VNC file for app %s", appUUID)
		os.Remove(types.VmiVNCFileName)
		return true
	}
	if isPortListening(existing.VNCPort) {
		log.Errorf("canClaimVNCFile: remote-console already active for app %s, cannot start for %s",
			existing.AppUUID, appUUID)
		return false
	}
	log.Noticef("canClaimVNCFile: removing stale remote-console VNC file for app %s",
		existing.AppUUID)
	os.Remove(types.VmiVNCFileName)
	return true
}

// isPortListening reports whether something is bound and listening on port on
// localhost. Delegates to netutils.IsLocalPortListening which reads
// /proc/net/tcp[6] directly — no Dial, so a live virtctl VNC proxy is not
// disturbed.
func isPortListening(port uint32) bool {
	return netutils.IsLocalPortListening(port)
}

func (z *zedkube) getVMIdomainName(config *types.AppInstanceConfig) (string, error) {
	if z.config == nil {
		config, err := kubeapi.GetKubeConfig()
		if err != nil {
			log.Errorf("getVMIs: config is nil")
			return "", fmt.Errorf("getVMIs: config get failed error %v", err)
		}
		z.config = config
	}
	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(z.config)
	if err != nil {
		log.Errorf("getVMIs: get virtclient error %v", err)
		return "", err
	}

	vmiName := base.GetAppKubeNameWithPurge(config.DisplayName, config.UUIDandVersion.UUID, config.PurgeCmd.Counter+config.LocalPurgeCmd.Counter)
	var domainName string
	vmis, err := virtClient.VirtualMachineInstance(kubeapi.EVEKubeNameSpace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("getVMIs: get VMI list error %v", err)
		return "", err
	}

	for _, vmi := range vmis.Items {
		if !strings.Contains(vmi.ObjectMeta.Name, vmiName) {
			continue
		}
		domainName = vmi.ObjectMeta.Name
		break
	}

	return domainName, nil
}
