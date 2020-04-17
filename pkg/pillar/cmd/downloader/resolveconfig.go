package downloader

import (
	"errors"
	"fmt"
	"net"
	"strings"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedUpload"
	log "github.com/sirupsen/logrus"
)

// Handles both create and modify events
func handleAppImgResolveModify(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	config := configArg.(types.ResolveConfig)
	log.Infof("handleAppImgResolveModify for %s\n", key)
	resolveTagsToHash(ctx, config)
	log.Infof("handleAppImgResolveModify for %s, done\n", key)
}

func handleAppImgResolveDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	ctx := ctxArg.(*downloaderContext)
	config := configArg.(types.ResolveConfig)
	ctx.pubAppImgResolveStatus.Unpublish(config.Key())
	log.Infof("handleAppImgResolveDelete for %s\n", key)
}

func publishResolveStatus(ctx *downloaderContext,
	status *types.ResolveStatus) {

	key := status.Key()
	log.Debugf("publishResolveStatus(%s)\n", key)
	pub := ctx.pubAppImgResolveStatus
	pub.Publish(key, *status)
	log.Debugf("publishResolveStatus(%s) Done\n", key)
}

func unpublishResolveStatus(ctx *downloaderContext,
	status *types.ResolveStatus) {

	key := status.Key()
	log.Debugf("unpublishResolveStatus(%s)\n", key)
	pub := ctx.pubAppImgResolveStatus
	pub.Unpublish(key)
	log.Debugf("unpublishResolveStatus(%s) Done\n", key)
}

func lookupResolveConfig(ctx *downloaderContext,
	key string) *types.ResolveConfig {

	sub := ctx.subAppImgResolveConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupResolveConfig(%s) not found\n", key)
		return nil
	}
	config := c.(types.ResolveConfig)
	return &config
}

func lookupResolveStatus(ctx *downloaderContext,
	key string) *types.ResolveStatus {

	pub := ctx.pubAppImgResolveStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupResolveStatus(%s) not found\n", key)
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

	log.Infof("Resolving config <%s> using %v allow non-free port\n",
		rc.Name, rc.AllowNonFreePort)

	var addrCount int
	if !rc.AllowNonFreePort {
		addrCount = types.CountLocalAddrFreeNoLinkLocal(ctx.deviceNetworkStatus)
		log.Infof("Have %d free management port addresses\n", addrCount)
		err = errors.New("No free IP management port addresses for download")
	} else {
		addrCount = types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus)
		log.Infof("Have %d any management port addresses\n", addrCount)
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
		log.Errorf("Error preparing to download. All errors:%s\n", errStr)
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
			log.Errorf("GetLocalAddr failed: %s\n", err)
			errStr = errStr + "\n" + err.Error()
			continue
		}
		ifname := types.GetMgmtPortFromAddr(ctx.deviceNetworkStatus, ipSrc)
		log.Infof("Using IP source %v if %s transport %v\n",
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
	log.Errorf("All source IP addresses failed. All errors:%s\n", errStr)
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
