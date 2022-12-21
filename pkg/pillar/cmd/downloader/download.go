// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/lf-edge/eve/libs/zedUpload"
	"github.com/lf-edge/eve/libs/zedUpload/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
)

func loadDownloadedParts(locFilename string) types.DownloadedParts {
	var downloadedParts types.DownloadedParts
	fd, err := os.Open(locFilename + progressFileSuffix)
	if err == nil {
		decoder := json.NewDecoder(fd)
		err = decoder.Decode(&downloadedParts)
		if err != nil {
			log.Errorf("failed to decode progress file: %s", err)
		}
		err := fd.Close()
		if err != nil {
			log.Errorf("failed to close progress file: %s", err)
		}
	}
	return downloadedParts
}

func saveDownloadedParts(locFilename string, downloadedParts types.DownloadedParts) {
	fd, err := os.Create(locFilename + progressFileSuffix)
	if err != nil {
		log.Errorf("error creating progress file: %s", err)
	} else {
		encoder := json.NewEncoder(fd)
		err = encoder.Encode(downloadedParts)
		if err != nil {
			log.Errorf("failed to encode progress file: %s", err)
		}
		err := fd.Close()
		if err != nil {
			log.Errorf("failed to close progress file: %s", err)
		}
	}
}

// download perform the actual download, given the necessary information.
// Returns the content-type of the object downloaded, normally from the
// Content-Type header, but subject to whatever the DronaRequest implementation
// determined it is, empty string if not available; and the error, if any.
// Returns a cancel bool to tell the caller to not retry using other
// interfaces or IP addresses.
func download(ctx *downloaderContext, trType zedUpload.SyncTransportType,
	status Status, syncOp zedUpload.SyncOpType, downloadURL string,
	auth *zedUpload.AuthInput, dpath, region string, maxsize uint64, ifname string,
	ipSrc net.IP, filename, locFilename string, certs [][]byte,
	receiveChan chan<- CancelChannel) (string, bool, error) {

	// create Endpoint
	var dEndPoint zedUpload.DronaEndPoint
	var err error
	var cancel bool
	switch trType {
	case zedUpload.SyncHttpTr, zedUpload.SyncSftpTr:
		dEndPoint, err = ctx.dCtx.NewSyncerDest(trType, downloadURL, dpath, auth)
	case zedUpload.SyncAzureTr:
		dEndPoint, err = ctx.dCtx.NewSyncerDest(trType, downloadURL, dpath, auth)
	case zedUpload.SyncAwsTr:
		dEndPoint, err = ctx.dCtx.NewSyncerDest(trType, region, dpath, auth)
	case zedUpload.SyncOCIRegistryTr:
		dEndPoint, err = ctx.dCtx.NewSyncerDest(trType, downloadURL, filename, auth)
	case zedUpload.SyncGSTr:
		dEndPoint, err = ctx.dCtx.NewSyncerDest(trType, "", dpath, auth)

	default:
		err = fmt.Errorf("unknown transfer type: %s", trType)
	}
	if err != nil {
		log.Errorf("NewSyncerDest failed: %s", err)
		return "", cancel, err
	}
	// check for proxies on the selected management port interface
	proxyLookupURL := zedcloud.IntfLookupProxyCfg(log, &ctx.deviceNetworkStatus, ifname, downloadURL, trType)
	proxyURL, err := zedcloud.LookupProxy(log, &ctx.deviceNetworkStatus, ifname, proxyLookupURL)
	if err == nil {
		if proxyURL != nil {
			log.Functionf("%s: Using proxy %s", trType, proxyURL.String())
			if len(certs) > 0 {
				log.Functionf("%s: Set server certs", trType)
				err = dEndPoint.WithSrcIPAndProxyAndHTTPSCerts(ipSrc, proxyURL, certs)
			} else {
				err = dEndPoint.WithSrcIPAndProxySelection(ipSrc, proxyURL)
			}
		} else {
			if len(certs) > 0 {
				log.Functionf("%s: Set server certs", trType)
				err = dEndPoint.WithSrcIPAndHTTPSCerts(ipSrc, certs)
			} else {
				err = dEndPoint.WithSrcIPSelection(ipSrc)
			}
		}
		if err != nil {
			log.Errorf("Set source IP failed: %s", err)
			return "", cancel, err
		}
	} else {
		log.Errorf("Lookup Proxy failed: %s", err)
		return "", cancel, err
	}

	var respChan = make(chan *zedUpload.DronaRequest)

	log.Functionf("%s syncOp for dpath:<%s>, region: <%s>, filename: <%s>, "+
		"downloadURL: <%s>, maxsize: %d, ifname: %s, ipSrc: %+v, locFilename: %s",
		trType, dpath, region, filename, downloadURL, maxsize, ifname, ipSrc,
		locFilename)

	downloadedParts := loadDownloadedParts(locFilename)
	downloadedPartsHash := downloadedParts.Hash()

	// create Request
	req := dEndPoint.NewRequest(syncOp, filename, locFilename,
		int64(maxsize), true, respChan)
	if req == nil {
		return "", cancel, errors.New("NewRequest failed")
	}
	req = req.WithDoneParts(downloadedParts)
	req = req.WithCancel(context.Background())
	defer req.Cancel()
	req = req.WithLogger(logger)

	// Tell caller where we can be cancelled
	cancelChan := make(chan Notify, 1)
	receiveChan <- cancelChan
	// if we are done before event from cancelChan do nothing
	doneChan := make(chan Notify)
	defer close(doneChan)
	go func() {
		select {
		case <-doneChan:
			// remove cancel channel
			receiveChan <- nil
		case <-cancelChan:
			cancel = true
			errStr := fmt.Sprintf("cancelled by user: <%s>, <%s>, <%s>",
				dpath, region, filename)
			log.Error(errStr)
			_ = req.Cancel()
		}
	}()

	req.Post()

	lastProgress := time.Now()
	for resp := range respChan {
		newDownloadedParts := resp.GetDoneParts()
		newDownloadedPartsHash := newDownloadedParts.Hash()
		if downloadedPartsHash != newDownloadedPartsHash {
			downloadedPartsHash = newDownloadedPartsHash
			downloadedParts = newDownloadedParts
			saveDownloadedParts(locFilename, downloadedParts)
		}

		if resp.IsDnUpdate() {
			currentSize, totalSize, progress := resp.Progress()
			log.Functionf("Update progress for %v: %v/%v",
				resp.GetLocalName(), currentSize, totalSize)
			// sometime, the download goes to an infinite loop,
			// showing it has downloaded, more than it is supposed to
			// aborting download, marking it as an error
			if currentSize > totalSize {
				errStr := fmt.Sprintf("Size '%v' provided in image config of '%s' is incorrect.\nDownload status (%v / %v). Aborting the download",
					totalSize, resp.GetLocalName(), currentSize, totalSize)
				log.Errorln(errStr)
				return "", cancel, errors.New(errStr)
			}
			// Did anything change since last update?
			change := status.Progress(progress, currentSize,
				totalSize)
			if !change {
				if time.Since(lastProgress) > maxStalledTime {
					err := fmt.Errorf("Cancelling due to no progress for %s in %v; size %d/%d",
						resp.GetLocalName(),
						time.Since(lastProgress),
						currentSize, totalSize)
					log.Error(err)
					return "", cancel, err
				}
			} else {
				lastProgress = time.Now()
			}
			continue
		}
		if syncOp == zedUpload.SyncOpDownload {
			err = resp.GetDnStatus()
		} else {
			_, err = resp.GetUpStatus()
		}
		if resp.IsError() {
			return "", cancel, err
		}
		log.Functionf("Done for %v size %d",
			resp.GetLocalName(), resp.GetAsize())
		return req.GetContentType(), cancel, nil
	}
	// if we got here, channel was closed
	// range ends on a closed channel, which is the equivalent of "!ok"
	errStr := fmt.Sprintf("respChan EOF for <%s>, <%s>, <%s>",
		dpath, region, filename)
	log.Errorln(errStr)
	return "", cancel, errors.New(errStr)
}

// objectMetaData resolves a tag to a sha and returns the sha
// Returns a cancel bool to tell the caller to not retry using other
// interfaces or IP addresses.
func objectMetadata(ctx *downloaderContext, trType zedUpload.SyncTransportType,
	syncOp zedUpload.SyncOpType, downloadURL string,
	auth *zedUpload.AuthInput, dpath, region string, ifname string,
	ipSrc net.IP, filename string, receiveChan chan<- CancelChannel) (string, bool, error) {

	// create Endpoint
	var dEndPoint zedUpload.DronaEndPoint
	var err error
	var cancel bool
	var sha256 string
	switch trType {
	case zedUpload.SyncOCIRegistryTr:
		dEndPoint, err = ctx.dCtx.NewSyncerDest(trType, downloadURL, filename, auth)
	default:
		err = fmt.Errorf("Not supported transport type: %s", trType)
	}
	if err != nil {
		log.Errorf("NewSyncerDest failed: %s", err)
		return sha256, cancel, err
	}
	// check for proxies on the selected management port interface
	proxyLookupURL := zedcloud.IntfLookupProxyCfg(log, &ctx.deviceNetworkStatus, ifname, downloadURL, trType)

	proxyURL, err := zedcloud.LookupProxy(log, &ctx.deviceNetworkStatus, ifname, proxyLookupURL)
	if err == nil && proxyURL != nil {
		log.Functionf("%s: Using proxy %s", trType, proxyURL.String())
		dEndPoint.WithSrcIPAndProxySelection(ipSrc, proxyURL)
	} else {
		dEndPoint.WithSrcIPSelection(ipSrc)
	}

	var respChan = make(chan *zedUpload.DronaRequest)

	log.Functionf("%s syncOp for dpath:<%s>, region: <%s>, filename: <%s>, "+
		"downloadURL: <%s>, ifname: %s, ipSrc: %+v",
		trType, dpath, region, filename, downloadURL, ifname, ipSrc)
	// create Request
	// Round up from bytes to Mbytes
	req := dEndPoint.NewRequest(syncOp, filename, "",
		0, true, respChan)
	if req == nil {
		return sha256, cancel, errors.New("NewRequest failed")
	}

	req = req.WithCancel(context.Background())
	defer req.Cancel()

	// Tell caller where we can be cancelled
	cancelChan := make(chan Notify, 1)
	receiveChan <- cancelChan
	// if we are done before event from cancelChan do nothing
	doneChan := make(chan Notify)
	defer close(doneChan)
	go func() {
		select {
		case <-doneChan:
			// remove cancel channel
			receiveChan <- nil
		case <-cancelChan:
			cancel = true
			errStr := fmt.Sprintf("cancelled by user: <%s>, <%s>, <%s>",
				dpath, region, filename)
			log.Error(errStr)
			_ = req.Cancel()
		}
	}()

	req.Post()

	lastProgress := time.Now()
	for resp := range respChan {
		if resp.IsDnUpdate() {
			if time.Since(lastProgress) > maxStalledTime {
				err := fmt.Errorf("Cancelling due to no progress for %s in %v",
					resp.GetLocalName(),
					time.Since(lastProgress))
				log.Error(err)
				return "", cancel, err
			}
			continue
		}
		if syncOp == zedUpload.SyncOpGetObjectMetaData {
			sha256 = resp.GetSha256()
			err = resp.GetDnStatus()
		} else {
			_, err = resp.GetUpStatus()
		}
		if resp.IsError() {
			return sha256, cancel, err
		}
		log.Functionf("Resolve config Done for %v: sha %v",
			filename, resp.GetSha256())
		return sha256, cancel, nil
	}
	// if we got here, channel was closed
	// range ends on a closed channel, which is the equivalent of "!ok"
	errStr := fmt.Sprintf("respChan EOF for <%s>, <%s>, <%s>",
		dpath, region, filename)
	log.Errorln(errStr)
	return sha256, cancel, errors.New(errStr)
}
