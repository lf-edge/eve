// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedUpload"
	log "github.com/sirupsen/logrus"
)

func runResolveHandler(ctx *downloaderContext, key string,
	isContentTree bool, c <-chan Notify) {

	log.Infof("runResolveHandler starting")

	max := float64(retryTime)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	closed := false
	for !closed {
		select {
		case _, ok := <-c:
			if ok {
				rc := lookupResolveConfig(ctx, key, isContentTree)
				resolveTagsToHash(ctx, *rc)
				// XXX if err start timer
			} else {
				// Closed
				rs := lookupResolveStatus(ctx, key)
				if rs != nil {
					unpublishResolveStatus(ctx, rs)
				}
				closed = true
				// XXX stop timer
			}
		case <-ticker.C:
			log.Debugf("runResolveHandler(%s) timer", key)
			rs := lookupResolveStatus(ctx, key)
			if rs != nil {
				maybeRetryResolve(ctx, rs, isContentTree)
			}
		}
	}
	log.Infof("runResolveHandler(%s) DONE", key)
}

func maybeRetryResolve(ctx *downloaderContext,
	status *types.ResolveStatus, isContentTree bool) {

	// object is either in download progress or,
	// successfully downloaded, nothing to do
	if !status.HasError() {
		return
	}
	t := time.Now()
	elapsed := t.Sub(status.ErrorTime)
	if elapsed < retryTime {
		log.Infof("maybeRetryResolve(%s) %d remaining",
			status.Key(),
			(retryTime-elapsed)/time.Second)
		return
	}
	log.Infof("maybeRetryResolve(%s) after %s at %v",
		status.Key(), status.Error, status.ErrorTime)

	config := lookupResolveConfig(ctx, status.Key(), isContentTree)
	if config == nil {
		log.Infof("maybeRetryResolve(%s) no config",
			status.Key())
		return
	}

	// reset Error, to start download again
	status.RetryCount++
	status.ClearError()
	publishResolveStatus(ctx, status)

	resolveTagsToHash(ctx, *config)
}

func publishResolveStatus(ctx *downloaderContext,
	status *types.ResolveStatus) {

	key := status.Key()
	log.Debugf("publishResolveStatus(%s)", key)
	pub := ctx.pubContentTreeResolveStatus
	pub.Publish(key, *status)
	log.Debugf("publishResolveStatus(%s) Done", key)
}

func unpublishResolveStatus(ctx *downloaderContext,
	status *types.ResolveStatus) {

	key := status.Key()
	log.Debugf("unpublishResolveStatus(%s)", key)
	pub := ctx.pubContentTreeResolveStatus
	pub.Unpublish(key)
	log.Debugf("unpublishResolveStatus(%s) Done", key)
}

func lookupResolveConfig(ctx *downloaderContext,
	key string, isContentTree bool) *types.ResolveConfig {

	var sub pubsub.Subscription
	if isContentTree {
		sub = ctx.subContentTreeResolveConfig
	} else {
		sub = ctx.subAppImgResolveConfig
	}
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupResolveConfig(%s) not found", key)
		return nil
	}
	config := c.(types.ResolveConfig)
	return &config
}

func lookupResolveStatus(ctx *downloaderContext,
	key string) *types.ResolveStatus {

	pub := ctx.pubContentTreeResolveStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupResolveStatus(%s) not found", key)
		return nil
	}
	status := c.(types.ResolveStatus)
	return &status
}

func resolveTagsToHash(ctx *downloaderContext, rc types.ResolveConfig) {
	var (
		err                           error
		errStr, remoteName, serverURL string
		syncOp                        zedUpload.SyncOpType = zedUpload.SyncOpGetObjectMetaData
		trType                        zedUpload.SyncTransportType
		auth                          *zedUpload.AuthInput
	)

	rs := lookupResolveStatus(ctx, rc.Key())
	if rs == nil {
		rs = &types.ResolveStatus{
			DatastoreID: rc.DatastoreID,
			Name:        rc.Name,
			Counter:     rc.Counter,
		}
	}
	rs.ClearError()

	sha := maybeNameHasSha(rc.Name)
	if sha != "" {
		rs.ImageSha256 = sha
		publishResolveStatus(ctx, rs)
		return
	}

	dst, errStr := lookupDatastoreConfig(ctx, rc.DatastoreID, rc.Name)
	if errStr != "" {
		rs.SetErrorNow(errStr)
		publishResolveStatus(ctx, rs)
		return
	}
	// construct the datastore context
	dsCtx, err := constructDatastoreContext(ctx, rc.Name, false, *dst)
	if err != nil {
		errStr := fmt.Sprintf("%s, Datastore construction failed, %s", rc.Name, err)
		rs.SetErrorNow(errStr)
		publishResolveStatus(ctx, rs)
		return
	}

	log.Infof("Resolving config <%s> using %v allow non-free port",
		rc.Name, rc.AllowNonFreePort)

	var addrCount int
	if !rc.AllowNonFreePort {
		addrCount = types.CountLocalAddrFreeNoLinkLocal(ctx.deviceNetworkStatus)
		log.Infof("Have %d free management port addresses", addrCount)
		err = errors.New("No free IP management port addresses for download")
	} else {
		addrCount = types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus)
		log.Infof("Have %d any management port addresses", addrCount)
		err = errors.New("No IP management port addresses for download")
	}
	if addrCount == 0 {
		rs.SetErrorNow(err.Error())
		publishResolveStatus(ctx, rs)
		return
	}

	switch dsCtx.TransportMethod {
	case zconfig.DsType_DsContainerRegistry.String():
		auth = &zedUpload.AuthInput{
			AuthType: "apikey",
			Uname:    dsCtx.APIKey,
			Password: dsCtx.Password,
		}
		trType = zedUpload.SyncOCIRegistryTr
		// get the name of the repository and the URL for the registry
		serverURL, remoteName, err = ociRepositorySplit(dsCtx.DownloadURL)
		if err != nil {
			errStr = fmt.Sprintf("invalid OCI registry URL: %s", serverURL)
		}

	default:
		errStr = "unsupported transport method " + dsCtx.TransportMethod

	}

	// if there were any errors, do not bother continuing
	// ideally in go we would have this as a check for error
	// and return, but we will get to it later
	if errStr != "" {
		log.Errorf("Error preparing to download. All errors:%s", errStr)
		rs.SetErrorNow(errStr)
		publishResolveStatus(ctx, rs)
		return
	}

	// Loop through all interfaces until a success
	for addrIndex := 0; addrIndex < addrCount; addrIndex++ {
		var ipSrc net.IP
		if !rc.AllowNonFreePort {
			ipSrc, err = types.GetLocalAddrFreeNoLinkLocal(ctx.deviceNetworkStatus,
				addrIndex, "")
		} else {
			// Note that GetLocalAddrAny has the free ones first
			ipSrc, err = types.GetLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus,
				addrIndex, "")
		}
		if err != nil {
			log.Errorf("GetLocalAddr failed: %s", err)
			errStr = errStr + "\n" + err.Error()
			continue
		}
		ifname := types.GetMgmtPortFromAddr(ctx.deviceNetworkStatus, ipSrc)
		log.Infof("Using IP source %v if %s transport %v",
			ipSrc, ifname, dsCtx.TransportMethod)

		sha256, err := objectMetadata(ctx, trType, syncOp, serverURL, auth,
			dsCtx.Dpath, dsCtx.Region,
			ifname, ipSrc, remoteName)
		if err != nil {
			errStr = errStr + "\n" + err.Error()
			continue
		}
		rs.ImageSha256 = sha256
		publishResolveStatus(ctx, rs)
		return

	}
	log.Errorf("All source IP addresses failed. All errors:%s", errStr)
	rs.SetErrorNow(errStr)
	publishResolveStatus(ctx, rs)
}

func maybeNameHasSha(name string) string {
	if strings.Contains(name, "@sha256:") {
		parts := strings.Split(name, "@sha256:")
		return strings.ToUpper(parts[1])
	}
	return ""
}
