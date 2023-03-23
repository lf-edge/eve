// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"fmt"
	"strings"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/libs/zedUpload"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	logutils "github.com/lf-edge/eve/pkg/pillar/utils/logging"
	uuid "github.com/satori/go.uuid"
)

func runResolveHandler(ctx *downloaderContext, key string, updateChan <-chan Notify,
	receiveChan chan<- CancelChannel) {

	log.Functionf("runResolveHandler starting")

	max := float64(retryTime)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	closed := false
	for !closed {
		select {
		case _, ok := <-updateChan:
			if ok {
				rc := lookupResolveConfig(ctx, key)
				resolveTagsToHash(ctx, *rc, receiveChan)
			} else {
				// Closed
				rs := lookupResolveStatus(ctx, key)
				if rs != nil {
					unpublishResolveStatus(ctx, rs)
				}
				closed = true
			}
		case <-ticker.C:
			log.Tracef("runResolveHandler(%s) timer", key)
			rs := lookupResolveStatus(ctx, key)
			if rs != nil {
				maybeRetryResolve(ctx, rs, receiveChan)
			}
		}
	}
	log.Functionf("runResolveHandler(%s) DONE", key)
}

func maybeRetryResolve(ctx *downloaderContext, status *types.ResolveStatus,
	receiveChan chan<- CancelChannel) {

	// object is either in download progress or,
	// successfully downloaded, nothing to do
	if !status.HasError() {
		return
	}
	config := lookupResolveConfig(ctx, status.Key())
	if config == nil {
		log.Functionf("maybeRetryResolve(%s) no config",
			status.Key())
		return
	}

	t := time.Now()
	elapsed := t.Sub(status.ErrorTime)
	if elapsed < retryTime {
		log.Functionf("maybeRetryResolve(%s) %d remaining",
			status.Key(),
			(retryTime-elapsed)/time.Second)
		return
	}
	log.Functionf("maybeRetryResolve(%s) after %s at %v",
		status.Key(), status.Error, status.ErrorTime)

	if status.RetryCount == 0 {
		status.OrigError = status.Error
	}
	// Increment count; we defer clearing error until success
	// to avoid confusing the user.
	status.RetryCount++
	severity := types.GetErrorSeverity(status.RetryCount, time.Duration(status.RetryCount)*retryTime)
	errDescription := types.ErrorDescription{
		Error:               status.OrigError,
		ErrorRetryCondition: fmt.Sprintf("Retrying; attempt %d", status.RetryCount),
		ErrorSeverity:       severity,
	}
	status.SetErrorDescription(errDescription)
	publishResolveStatus(ctx, status)

	resolveTagsToHash(ctx, *config, receiveChan)
}

func publishResolveStatus(ctx *downloaderContext,
	status *types.ResolveStatus) {

	key := status.Key()
	log.Tracef("publishResolveStatus(%s)", key)
	pub := ctx.pubResolveStatus
	pub.Publish(key, *status)
	log.Tracef("publishResolveStatus(%s) Done", key)
}

func unpublishResolveStatus(ctx *downloaderContext,
	status *types.ResolveStatus) {

	key := status.Key()
	log.Tracef("unpublishResolveStatus(%s)", key)
	pub := ctx.pubResolveStatus
	pub.Unpublish(key)
	log.Tracef("unpublishResolveStatus(%s) Done", key)
}

func lookupResolveConfig(ctx *downloaderContext, key string) *types.ResolveConfig {

	sub := ctx.subResolveConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Functionf("lookupResolveConfig(%s) not found", key)
		return nil
	}
	config := c.(types.ResolveConfig)
	return &config
}

func lookupResolveStatus(ctx *downloaderContext,
	key string) *types.ResolveStatus {

	pub := ctx.pubResolveStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Functionf("lookupResolveStatus(%s) not found", key)
		return nil
	}
	status := c.(types.ResolveStatus)
	return &status
}

func resolveTagsToHash(ctx *downloaderContext, rc types.ResolveConfig,
	receiveChan chan<- CancelChannel) {

	var (
		err                           error
		errStr, remoteName, serverURL string
		syncOp                        zedUpload.SyncOpType = zedUpload.SyncOpGetObjectMetaData
		trType                        zedUpload.SyncTransportType
		auth                          *zedUpload.AuthInput
		sha256                        string
		cancelled                     bool
	)

	rs := lookupResolveStatus(ctx, rc.Key())
	if rs == nil {
		rs = &types.ResolveStatus{
			DatastoreID: rc.DatastoreID,
			Name:        rc.Name,
			Counter:     rc.Counter,
		}
	}
	sha := maybeNameHasSha(rc.Name)
	if sha != "" {
		rs.ImageSha256 = sha
		publishResolveStatus(ctx, rs)
		return
	}

	dst, err := utils.LookupDatastoreConfig(ctx.subDatastoreConfig, rc.DatastoreID)
	if err != nil {
		severity := types.GetErrorSeverity(rs.RetryCount, time.Duration(rs.RetryCount)*retryTime)
		errDescription := types.ErrorDescription{
			Error:               err.Error(),
			ErrorRetryCondition: fmt.Sprintf("Will retry when datastore available"),
			ErrorSeverity:       severity,
		}
		rs.SetErrorDescription(errDescription)
		publishResolveStatus(ctx, rs)
		return
	}
	log.Tracef("Found datastore(%s) for %s", rc.DatastoreID.String(), rc.Name)

	// construct the datastore context
	dsCtx, err := constructDatastoreContext(ctx, rc.Name, false, *dst)
	if err != nil {
		severity := types.GetErrorSeverity(rs.RetryCount, time.Duration(rs.RetryCount)*retryTime)
		errDescription := types.ErrorDescription{
			Error:               err.Error(),
			ErrorRetryCondition: fmt.Sprintf("Will retry in %s; have retried %d times", retryTime, rs.RetryCount),
			ErrorSeverity:       severity,
		}
		rs.SetErrorDescription(errDescription)
		publishResolveStatus(ctx, rs)
		return
	}

	downloadMaxPortCost := ctx.downloadMaxPortCost
	log.Functionf("Resolving config <%s> using %d downloadMaxPortCost",
		rc.Name, downloadMaxPortCost)

	addrCount := types.CountLocalAddrNoLinkLocalWithCost(ctx.deviceNetworkStatus,
		downloadMaxPortCost)
	log.Functionf("Have %d management port addresses for cost %d",
		addrCount, downloadMaxPortCost)
	if addrCount == 0 {
		err := fmt.Errorf("No IP management port addresses with cost <= %d",
			downloadMaxPortCost)
		log.Error(err.Error())
		severity := types.GetErrorSeverity(rs.RetryCount, time.Duration(rs.RetryCount)*retryTime)
		errDescription := types.ErrorDescription{
			Error:               err.Error(),
			ErrorRetryCondition: fmt.Sprintf("Will retry in %s; have retried %d times", retryTime, rs.RetryCount),
			ErrorSeverity:       severity,
		}
		rs.SetErrorDescription(errDescription)
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
			errStr = fmt.Sprintf("invalid OCI registry URL: %s", err.Error())
		}

	default:
		errStr = "unsupported transport method " + dsCtx.TransportMethod

	}

	// if there were any errors, do not bother continuing
	// ideally in go we would have this as a check for error
	// and return, but we will get to it later
	if errStr != "" {
		log.Errorf("Error preparing to download. All errors:%s", errStr)
		severity := types.GetErrorSeverity(rs.RetryCount, time.Duration(rs.RetryCount)*retryTime)
		errDescription := types.ErrorDescription{
			Error:               errStr,
			ErrorRetryCondition: fmt.Sprintf("Will retry in %s; have retried %d times", retryTime, rs.RetryCount),
			ErrorSeverity:       severity,
		}
		rs.SetErrorDescription(errDescription)
		publishResolveStatus(ctx, rs)
		return
	}

	// Loop through all interfaces until a success
	for addrIndex := 0; addrIndex < addrCount; addrIndex++ {
		ipSrc, err := types.GetLocalAddrNoLinkLocalWithCost(ctx.deviceNetworkStatus,
			addrIndex, "", downloadMaxPortCost)
		if err != nil {
			log.Errorf("GetLocalAddr failed: %s", err)
			errStr = errStr + "\n" + err.Error()
			continue
		}
		ifname := types.GetMgmtPortFromAddr(ctx.deviceNetworkStatus, ipSrc)
		log.Functionf("Using IP source %v if %s transport %v",
			ipSrc, ifname, dsCtx.TransportMethod)

		sha256, cancelled, err = objectMetadata(ctx, trType, syncOp, serverURL, auth,
			dsCtx.Dpath, dsCtx.Region,
			ifname, ipSrc, remoteName, receiveChan)
		if err != nil {
			if cancelled {
				errStr = "tag resolution cancelled by user"
				break
			}
			// to catch and skip the oci manifest error with the suffix of "no suitable address found"
			if !strings.HasSuffix(err.Error(), logutils.NoSuitableAddrStr) {
				errStr = errStr + "\n" + err.Error()
			}
			continue
		}
		rs.ClearError()
		rs.ImageSha256 = sha256
		publishResolveStatus(ctx, rs)
		return

	}
	// we skip this error earlier but we must fill errStr
	if errStr == "" {
		errStr = logutils.NoSuitableAddrStr
	}
	if !cancelled {
		log.Errorf("All source IP addresses failed. All errors:%s",
			errStr)
		severity := types.GetErrorSeverity(rs.RetryCount, time.Duration(rs.RetryCount)*retryTime)
		errDescription := types.ErrorDescription{
			Error:               errStr,
			ErrorRetryCondition: fmt.Sprintf("Will retry in %s; have retried %d times", retryTime, rs.RetryCount),
			ErrorSeverity:       severity,
		}
		rs.SetErrorDescription(errDescription)
	} else {
		rs.SetErrorDescription(types.ErrorDescription{
			Error: errStr,
		})
	}
	publishResolveStatus(ctx, rs)
}

func maybeNameHasSha(name string) string {
	if strings.Contains(name, "@sha256:") {
		parts := strings.Split(name, "@sha256:")
		return strings.ToUpper(parts[1])
	}
	return ""
}

// checkAndUpdateResolveConfig fires modify handler for ResolveConfig
// we need to call it in case of no DatastoreConfig found
func checkAndUpdateResolveConfig(ctx *downloaderContext, dsID uuid.UUID) {
	log.Functionf("checkAndUpdateResolveConfig for %s", dsID)
	resolveStatuses := ctx.pubResolveStatus.GetAll()
	for _, v := range resolveStatuses {
		status := v.(types.ResolveStatus)
		if status.DatastoreID == dsID {
			config := lookupResolveConfig(ctx, status.Key())
			if config != nil {
				log.Noticef("checkAndUpdateResolveConfig updating %s due to datastore %s",
					status.Key(), dsID)
				resHandler.modify(ctx, status.Key(), *config, *config)
			}
		}
	}
	log.Functionf("checkAndUpdateResolveConfig for %s, done", dsID)
}
