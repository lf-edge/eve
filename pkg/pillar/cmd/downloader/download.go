package downloader

import (
	"errors"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/lf-edge/eve/pkg/pillar/zedUpload"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
)

// perform the actual download
func download(ctx *downloaderContext, trType zedUpload.SyncTransportType,
	status Status, syncOp zedUpload.SyncOpType, downloadURL string,
	auth *zedUpload.AuthInput, dpath, region string, maxsize uint64, ifname string,
	ipSrc net.IP, filename, locFilename string) error {

	// create Endpoint
	var dEndPoint zedUpload.DronaEndPoint
	var err error
	if trType == zedUpload.SyncHttpTr || trType == zedUpload.SyncSftpTr {
		dEndPoint, err = ctx.dCtx.NewSyncerDest(trType, downloadURL, dpath, auth)
	} else if trType == zedUpload.SyncAzureTr {
		dEndPoint, err = ctx.dCtx.NewSyncerDest(trType, "", dpath, auth)
	} else {
		// AWS
		dEndPoint, err = ctx.dCtx.NewSyncerDest(trType, region, dpath, auth)
	}
	if err != nil {
		log.Errorf("NewSyncerDest failed: %s\n", err)
		return err
	}
	// check for proxies on the selected management port interface
	proxyUrl, err := zedcloud.LookupProxy(
		&ctx.deviceNetworkStatus, ifname, downloadURL)
	if err == nil && proxyUrl != nil {
		log.Infof("%s: Using proxy %s", trType, proxyUrl.String())
		dEndPoint.WithSrcIpAndProxySelection(ipSrc, proxyUrl)
	} else {
		dEndPoint.WithSrcIpSelection(ipSrc)
	}

	var respChan = make(chan *zedUpload.DronaRequest)

	log.Infof("%s syncOp for <%s>, <%s>, <%s>\n", trType, dpath, region, filename)
	// create Request
	// Round up from bytes to Mbytes
	maxMB := (maxsize + 1024*1024 - 1) / (1024 * 1024)
	req := dEndPoint.NewRequest(syncOp, filename, locFilename,
		int64(maxMB), true, respChan)
	if req == nil {
		return errors.New("NewRequest failed")
	}

	req.Post()
	for resp := range respChan {
		if resp.IsDnUpdate() {
			asize, osize, progress := resp.Progress()
			log.Infof("Update progress for %v: %v/%v",
				resp.GetLocalName(), asize, osize)
			status.Progress(progress)
			continue
		}
		if syncOp == zedUpload.SyncOpDownload {
			err = resp.GetDnStatus()
		} else {
			_, err = resp.GetUpStatus()
		}
		if resp.IsError() {
			return err
		}
		log.Infof("Done for %v: size %v/%v",
			resp.GetLocalName(),
			resp.GetAsize(), resp.GetOsize())
		status.Progress(100)
		return nil
	}
	// if we got here, channel was closed
	// range ends on a closed channel, which is the equivalent of "!ok"
	errStr := fmt.Sprintf("respChan EOF for <%s>, <%s>, <%s>",
		dpath, region, filename)
	log.Errorln(errStr)
	return errors.New(errStr)
}
