// Copyright (c) 2020-2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package msrv

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
)

func (srv *Msrv) lookupAppNetworkStatusByAppIP(ip net.IP) *types.AppNetworkStatus {
	sub := srv.subAppNetworkStatus
	items := sub.GetAll()
	for _, st := range items {
		status := st.(types.AppNetworkStatus)
		for _, adapterStatus := range status.AppNetAdapterList {
			if adapterStatus.AllocatedIPv4Addr.Equal(ip) {
				return &status
			}
		}
	}
	return nil
}

func (srv *Msrv) getExternalIPForApp(remoteIP net.IP) (net.IP, int) {
	netstatus := srv.lookupNetworkInstanceStatusByAppIP(remoteIP)
	if netstatus == nil {
		srv.Log.Errorf("getExternalIPForApp: No NetworkInstanceStatus for %v", remoteIP)
		return nil, http.StatusNotFound
	}
	if netstatus.SelectedUplinkIntfName == "" {
		srv.Log.Warnf("getExternalIPForApp: No SelectedUplinkIntfName for %v", remoteIP)
		// Nothing to report */
		return nil, http.StatusNoContent
	}
	ip, err := types.GetLocalAddrAnyNoLinkLocal(*srv.deviceNetworkStatus,
		0, netstatus.SelectedUplinkIntfName)
	if err != nil {
		srv.Log.Errorf("getExternalIPForApp: No externalIP for %s: %s",
			remoteIP.String(), err)
		return nil, http.StatusNoContent
	}
	return ip, http.StatusOK
}

func (srv *Msrv) lookupNetworkInstanceStatusByAppIP(
	ip net.IP) *types.NetworkInstanceStatus {
	pub := srv.subNetworkInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.NetworkInstanceStatus)
		for _, addrs := range status.IPAssignments {
			if ip.Equal(addrs.IPv4Addr) {
				return &status
			}
			for _, nip := range addrs.IPv6Addrs {
				if ip.Equal(nip) {
					return &status
				}
			}
		}
	}
	return nil
}

func (srv *Msrv) lookupAppInstMetadata(key string) *types.AppInstMetaData {
	pub := srv.pubAppInstMetaData
	st, _ := pub.Get(key)
	if st == nil {
		srv.Log.Tracef("lookupAppInstMetadata: key %s not found", key)
		return nil
	}
	appInstMetadata := st.(types.AppInstMetaData)
	return &appInstMetadata
}

func (srv *Msrv) getSSHPublicKeys(dc *types.AppNetworkConfig) []string {
	// TBD: add ssh keys into cypher block
	return nil
}

func (srv *Msrv) getCloudInitUserData(dc *types.AppNetworkConfig) (string, error) {
	if dc.CipherBlockStatus.IsCipher {
		status, decBlock, err := cipher.GetCipherCredentials(
			&srv.decryptCipherContext, dc.CipherBlockStatus)
		if err != nil {
			_ = srv.pubCipherBlockStatus.Publish(status.Key(), status)
		}
		if err != nil {
			srv.Log.Errorf("%s, AppNetworkConfig CipherBlock decryption unsuccessful, "+
				"falling back to cleartext: %v", dc.Key(), err)
			if dc.CloudInitUserData == nil {
				srv.cipherMetrics.RecordFailure(srv.Log, types.MissingFallback)
				return decBlock.ProtectedUserData, fmt.Errorf(
					"AppNetworkConfig CipherBlock decryption"+
						"unsuccessful (%s); no fallback data", err)
			}
			decBlock.ProtectedUserData = *dc.CloudInitUserData
			// We assume IsCipher is only set when there was some
			// data, hence this is a fallback if there is some cleartext.
			if decBlock.ProtectedUserData != "" {
				srv.cipherMetrics.RecordFailure(srv.Log, types.CleartextFallback)
			} else {
				srv.cipherMetrics.RecordFailure(srv.Log, types.MissingFallback)
			}
			return decBlock.ProtectedUserData, nil
		}
		srv.Log.Functionf("%s, AppNetworkConfig CipherBlock decryption successful",
			dc.Key())
		return decBlock.ProtectedUserData, nil
	}
	srv.Log.Functionf("%s, AppNetworkConfig CipherBlock not present", dc.Key())
	decBlock := types.EncryptionBlock{}
	if dc.CloudInitUserData == nil {
		srv.cipherMetrics.RecordFailure(srv.Log, types.NoCipher)
		return decBlock.ProtectedUserData, nil
	}
	decBlock.ProtectedUserData = *dc.CloudInitUserData
	if decBlock.ProtectedUserData != "" {
		srv.cipherMetrics.RecordFailure(srv.Log, types.NoCipher)
	} else {
		srv.cipherMetrics.RecordFailure(srv.Log, types.NoData)
	}
	return decBlock.ProtectedUserData, nil
}

func (srv *Msrv) lookupAppNetworkConfig(key string) *types.AppNetworkConfig {
	sub := srv.subAppNetworkConfig
	c, _ := sub.Get(key)
	if c == nil {
		sub = srv.subAppNetworkConfigAg
		c, _ = sub.Get(key)
		if c == nil {
			srv.Log.Tracef("lookupAppNetworkConfig(%s) not found", key)
			return nil
		}
	}
	config := c.(types.AppNetworkConfig)
	return &config
}

func (srv *Msrv) publishAppInstMetadata(appInstMetadata *types.AppInstMetaData) {
	if appInstMetadata == nil {
		srv.Log.Errorf("publishAppInstMetadata: nil appInst metadata")
		return
	}
	key := appInstMetadata.Key()
	pub := srv.pubAppInstMetaData
	err := pub.Publish(key, *appInstMetadata)
	if err != nil {
		srv.Log.Errorf("publishAppInstMetadata failed: %v", err)
	}
}

func (srv *Msrv) unpublishAppInstMetadata(appInstMetadata *types.AppInstMetaData) {
	if appInstMetadata == nil {
		srv.Log.Errorf("unpublishAppInstMetadata: nil appInst metadata")
		return
	}
	key := appInstMetadata.Key()
	pub := srv.pubAppInstMetaData
	if exists, _ := pub.Get(key); exists == nil {
		srv.Log.Errorf("unpublishAppInstMetadata: key %s not found", key)
		return
	}
	err := pub.Unpublish(key)
	if err != nil {
		srv.Log.Errorf("unpublishAppInstMetadata failed: %v", err)
	}
}

func (srv *Msrv) lookupDiskStatusList(key string) []types.DiskStatus {
	st, err := srv.subDomainStatus.Get(key)
	if err != nil || st == nil {
		srv.Log.Warnf("lookupDiskStatusList: could not find domain %s", key)
		return nil
	}
	domainStatus := st.(types.DomainStatus)
	return domainStatus.DiskStatusList
}

func (srv *Msrv) increasePatchEnvelopeStatusCounter(appUUID string, patch types.PatchEnvelopeInfo) {
	defaultValue := types.PatchEnvelopeUsage{
		AppUUID: appUUID,
		PatchID: patch.PatchID,
		Version: patch.Version,

		PatchAPICallCount: 1,
		DownloadCount:     0,
	}
	incrementFn := func(v types.PatchEnvelopeUsage) types.PatchEnvelopeUsage {
		v.PatchAPICallCount++
		return v
	}
	srv.patchEnvelopesUsage.ApplyOrStore(defaultValue.Key(), incrementFn, defaultValue)
}

func (srv *Msrv) increasePatchEnvelopeDownloadCounter(appUUID string, patch types.PatchEnvelopeInfo) {
	defaultValue := types.PatchEnvelopeUsage{
		AppUUID: appUUID,
		PatchID: patch.PatchID,
		Version: patch.Version,

		PatchAPICallCount: 0,
		DownloadCount:     1,
	}
	incrementFn := func(v types.PatchEnvelopeUsage) types.PatchEnvelopeUsage {
		v.DownloadCount++
		return v
	}
	srv.patchEnvelopesUsage.ApplyOrStore(defaultValue.Key(), incrementFn, defaultValue)
}

// PublishPatchEnvelopesUsage publishes usage info for PatchEnvelopes and stores it in persist.
func (srv *Msrv) PublishPatchEnvelopesUsage() {
	publishFn := func(_ string, peUsage types.PatchEnvelopeUsage) bool {
		key := peUsage.Key()
		pub := srv.pubPatchEnvelopesUsage
		err := pub.Publish(key, peUsage)
		if err != nil {
			srv.Log.Errorf("publishPatchEnvelopesUsage failed: %v", err)
		}

		// save peUsage in persistcache
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		if err = enc.Encode(peUsage); err != nil {
			srv.Log.Errorf("publishPatchEnvelopesUsage failed to encode peUsage: %v", err)
		}
		_, err = srv.peUsagePersist.Put(key, buf.Bytes())
		if err != nil {
			srv.Log.Errorf("publishPatchEnvelopesUsage failed to store usage: %v", err)
		}

		return true
	}
	srv.patchEnvelopesUsage.Range(publishFn)
}

func (srv *Msrv) handlePatchEnvelopeImpl(peInfo types.PatchEnvelopeInfoList) {
	srv.Log.Noticef("start handlePatchEnvelopeImpl")

	before := srv.PatchEnvelopes.EnvelopesInUsage()
	srv.PatchEnvelopes.UpdateEnvelopes(peInfo.Envelopes)
	srv.triggerPEUpdate()

	// Delete stale files
	var after []string
	for _, pe := range peInfo.Envelopes {
		peUsages := types.PatchEnvelopeUsageFromInfo(pe)
		for _, usage := range peUsages {
			after = append(after, usage.Key())
		}
	}

	toDelete, _ := generics.DiffSets(before, after)
	for _, uuid := range toDelete {
		srv.patchEnvelopesUsage.Delete(uuid)
		srv.peUsagePersist.Delete(uuid)
	}

	srv.Log.Noticef("finish handlePatchEnvelopeImpl")
}

func (srv *Msrv) handlePatchEnvelopeCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	peInfo := configArg.(types.PatchEnvelopeInfoList)
	srv.Log.Functionf("handlePatchEnvelopeCreate: (UUID: %s) %v", key, peInfo.Envelopes)

	if len(peInfo.Envelopes) == 0 {
		srv.Log.Functionf("handlePatchEnvelopeCreate: (UUID: %s). Empty envelopes", key)
		return
	}

	srv.handlePatchEnvelopeImpl(peInfo)

	srv.Log.Functionf("handlePatchEnvelopeCreate(%s) done", key)
}

func (srv *Msrv) handlePatchEnvelopeModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	peInfo := statusArg.(types.PatchEnvelopeInfoList)

	if len(peInfo.Envelopes) == 0 {
		srv.Log.Functionf("handlePatchEnvelopeModify: (UUID: %s). Empty envelopes", key)
		return
	}

	srv.Log.Functionf("handlePatchEnvelopeModify: (UUID: %s) %v", key, peInfo.Envelopes)

	srv.handlePatchEnvelopeImpl(peInfo)

	srv.Log.Functionf("handlePatchEnvelopeModify(%s) done", key)
}

func (srv *Msrv) handlePatchEnvelopeDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	srv.Log.Functionf("handlePatchEnvelopeDelete: (UUID: %s)", key)

	srv.handlePatchEnvelopeImpl(types.PatchEnvelopeInfoList{})

	srv.Log.Functionf("handlePatchEnvelopeDelete(%s) done", key)
}

func (srv *Msrv) handleContentTreeStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	contentTree := statusArg.(types.ContentTreeStatus)
	srv.Log.Functionf("handleContentTreeStatusCreate: (UUID: %s, name:%s)",
		key, contentTree.DisplayName)

	srv.PatchEnvelopes.UpdateContentTree(contentTree, false)

	srv.triggerPEUpdate()

	srv.Log.Functionf("handleContentTreeStatusCreate(%s) done", key)
}

func (srv *Msrv) handleContentTreeStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {

	contentTree := statusArg.(types.ContentTreeStatus)
	srv.Log.Functionf("handleContentTreeStatusModify: (UUID: %s), name:%s",
		key, contentTree.DisplayName)

	srv.PatchEnvelopes.UpdateContentTree(contentTree, false)

	srv.triggerPEUpdate()

	srv.Log.Functionf("handleContentTreeStatusModify(%s) done", key)

}

func (srv *Msrv) handleContentTreeStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	contentTree := statusArg.(types.ContentTreeStatus)
	srv.Log.Functionf("handleVolumeStatusDelete: (UUID: %s, name:%s)",
		key, contentTree.DisplayName)

	srv.PatchEnvelopes.UpdateContentTree(contentTree, true)

	srv.triggerPEUpdate()

	srv.Log.Functionf("handleContentTreeStatusDelete(%s) done", key)

}

func (srv *Msrv) handleVolumeStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	volume := statusArg.(types.VolumeStatus)
	srv.Log.Functionf("handleVolumeStatusCreate: (UUID: %s, name:%s)",
		key, volume.DisplayName)

	srv.PatchEnvelopes.UpdateVolumeStatus(volume, false)

	srv.triggerPEUpdate()

	srv.Log.Functionf("Patch Envelopes handleVolumeStatusCreate(%s) done", key)
}

func (srv *Msrv) handleVolumeStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {

	volume := statusArg.(types.VolumeStatus)
	srv.Log.Functionf("handleVolumeStatusModify: (UUID: %s), name:%s",
		key, volume.DisplayName)

	srv.PatchEnvelopes.UpdateVolumeStatus(volume, false)

	srv.triggerPEUpdate()

	srv.Log.Functionf("Patch Envelopes handleVolumeStatusModify(%s) done", key)
}

func (srv *Msrv) handleVolumeStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	volume := statusArg.(types.VolumeStatus)
	srv.Log.Functionf("Patch Envelopes handleVolumeStatusDelete: (UUID: %s, name:%s)",
		key, volume.DisplayName)

	srv.PatchEnvelopes.UpdateVolumeStatus(volume, true)

	srv.triggerPEUpdate()

	srv.Log.Functionf("handleVolumeStatusDelete(%s) done", key)
}

func (srv *Msrv) triggerPEUpdate() {
	select {
	case srv.PatchEnvelopes.UpdateStateNotificationCh() <- struct{}{}:
		srv.Log.Function("triggerPEUpdate sent update")
	default:
		srv.Log.Warn("patchEnvelopes did not sent update. Slow handler?")
	}
}

func (srv *Msrv) handleGlobalConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	srv.handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func (srv *Msrv) handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	srv.handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func (srv *Msrv) handleGlobalConfigImpl(ctxArg interface{}, key string,
	statusArg interface{}) {
	if key != "global" {
		srv.Log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	srv.Log.Functionf("handleGlobalConfigImpl for %s", key)
	gcp := agentlog.HandleGlobalConfig(srv.Log, srv.subGlobalConfig, agentName,
		srv.CLIParams().DebugOverride, srv.Logger)
	if gcp != nil {
		srv.gcInitialized = true
		metricInterval := gcp.GlobalValueInt(types.MetricInterval)
		if metricInterval != 0 && srv.metricInterval != metricInterval {
			if srv.publishTicker != nil {
				interval := time.Duration(metricInterval) * time.Second
				max := float64(interval) / publishTickerDivider
				min := max * 0.3
				srv.publishTicker.UpdateRangeTicker(time.Duration(min), time.Duration(max))
			}
			srv.metricInterval = metricInterval
		}
	}
	srv.Log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func (srv *Msrv) handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	if key != "global" {
		srv.Log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	srv.Log.Functionf("handleGlobalConfigDelete for %s", key)
	agentlog.HandleGlobalConfig(srv.Log, srv.subGlobalConfig, agentName,
		srv.CLIParams().DebugOverride, srv.Logger)
	srv.Log.Functionf("handleGlobalConfigDelete done for %s", key)
}

func (srv *Msrv) handleAppInstDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	srv.Log.Functionf("handleAppInstDelete(%s)", key)
	appInstMetadata := srv.lookupAppInstMetadata(key)
	if appInstMetadata == nil {
		srv.Log.Functionf("handleAppInstDelete: unknown %s", key)
		return
	}
	// Clean up appInst Metadata
	srv.unpublishAppInstMetadata(appInstMetadata)
	srv.Log.Functionf("handleAppInstDelete(%s) done", key)
}
