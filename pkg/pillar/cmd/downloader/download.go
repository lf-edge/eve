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

	"github.com/lf-edge/eve/libs/nettrace"
	"github.com/lf-edge/eve/libs/zedUpload"
	"github.com/lf-edge/eve/libs/zedUpload/types"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
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
	ipSrc net.IP, filename, locFilename string, certs [][]byte, withNetTracing bool,
	traceOpts []nettrace.TraceOpt, receiveChan chan<- CancelChannel) (
	reqType string, cancel bool, tracedReq netdump.TracedNetRequest, err error) {

	// create Endpoint
	var dEndPoint zedUpload.DronaEndPoint
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
		return "", cancel, tracedReq, err
	}
	defer dEndPoint.Close()

	// Configure the network client.
	err = dEndPoint.WithSrcIP(ipSrc)
	if err != nil {
		// If we failed to set source IP, then just log error and still try to download.
		// This behaviour is primarily because zedUpload package does not support statically
		// selected source IP for SFTP datastore and historically we would simply ignore this
		// limitation and continue with whatever source address was dynamically selected.
		// With other (currently supported) datastore types this call will not fail.
		log.Errorf("Set source IP failed: %s", err)
		err = nil
	}
	if len(certs) > 0 {
		log.Functionf("%s: Set trusted certs", trType)
		err = dEndPoint.WithTrustedCerts(certs)
		if err != nil {
			log.Errorf("Set trusted certificates failed: %s", err)
			return "", cancel, tracedReq, err
		}
	}
	// check for proxies on the selected management port interface
	proxyLookupURL := zedcloud.IntfLookupProxyCfg(log, &ctx.deviceNetworkStatus, ifname, downloadURL, trType)
	proxyURL, err := zedcloud.LookupProxy(log, &ctx.deviceNetworkStatus, ifname, proxyLookupURL)
	if err != nil {
		log.Errorf("Lookup Proxy failed: %s", err)
		return "", cancel, tracedReq, err
	}
	if proxyURL != nil {
		log.Functionf("%s: Using proxy %s", trType, proxyURL.String())
		err = dEndPoint.WithProxy(proxyURL)
		if err != nil {
			log.Errorf("Set proxy failed: %s", err)
			return "", cancel, tracedReq, err
		}
	}

	downloadedParts := loadDownloadedParts(locFilename)
	downloadedPartsHash := downloadedParts.Hash()
	preDownloadParts := downloadedParts

	// If the download request is being traced and PCAP is enabled, the function
	// will wait just a little bit at the end to capture all the packets.
	const pcapDelay = 250 * time.Millisecond
	var withPCAP bool
	if withNetTracing {
		for _, traceOpt := range traceOpts {
			if _, ok := traceOpt.(*nettrace.WithPacketCapture); ok {
				withPCAP = true
				break
			}
		}
	}

	if withNetTracing {
		err = dEndPoint.WithNetTracing(traceOpts...)
		if err != nil {
			// Just log warning and disable network tracing.
			log.Warnf("Failed to enable network tracing: %s", err)
			err = nil
			withNetTracing = false
		} else {
			// Obtain and set netTrace at the end.
			// (but before Close(), which is below on the defer stack)
			defer func() {
				if withPCAP {
					time.Sleep(pcapDelay)
				}
				description := fmt.Sprintf("%v download URL: %s, dpath: %s, "+
					"region: %s, filename: %s, maxsize: %d, ifname: %s, ipSrc: %v, "+
					"locFilename: %s", trType, downloadURL, dpath, region, filename, maxsize,
					ifname, ipSrc, locFilename)
				// Use err2 to not change the return value of err.
				preDownloadProg, err2 := json.Marshal(preDownloadParts)
				if err2 == nil {
					description += ", pre-download progress: " + string(preDownloadProg)
				}
				postDownloadProg, err2 := json.Marshal(downloadedParts)
				if err2 == nil {
					description += ", post-download progress: " + string(postDownloadProg)
				}
				netTrace, pcaps, err2 := dEndPoint.GetNetTrace(description)
				if err2 != nil {
					log.Warnf("Failed to get network trace: %v", err2)
				} else {
					tracedReq.NetTrace = netTrace
					tracedReq.PacketCaptures = pcaps
				}
			}()
		}
	}

	var respChan = make(chan *zedUpload.DronaRequest)

	log.Functionf("%s syncOp for dpath:<%s>, region: <%s>, filename: <%s>, "+
		"downloadURL: <%s>, maxsize: %d, ifname: %s, ipSrc: %+v, locFilename: %s",
		trType, dpath, region, filename, downloadURL, maxsize, ifname, ipSrc,
		locFilename)

	// create Request
	req := dEndPoint.NewRequest(syncOp, filename, locFilename,
		int64(maxsize), true, respChan)
	if req == nil {
		return "", cancel, tracedReq, errors.New("NewRequest failed")
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
				return "", cancel, tracedReq, errors.New(errStr)
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
					return "", cancel, tracedReq, err
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
			return "", cancel, tracedReq, err
		}
		log.Functionf("Done for %v size %d",
			resp.GetLocalName(), resp.GetAsize())
		return req.GetContentType(), cancel, tracedReq, nil
	}
	// if we got here, channel was closed
	// range ends on a closed channel, which is the equivalent of "!ok"
	errStr := fmt.Sprintf("respChan EOF for <%s>, <%s>, <%s>",
		dpath, region, filename)
	log.Errorln(errStr)
	return "", cancel, tracedReq, errors.New(errStr)
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
	defer dEndPoint.Close()

	// Configure the network client.
	dEndPoint.WithSrcIP(ipSrc)
	// check for proxies on the selected management port interface
	proxyLookupURL := zedcloud.IntfLookupProxyCfg(log, &ctx.deviceNetworkStatus, ifname, downloadURL, trType)
	proxyURL, err := zedcloud.LookupProxy(log, &ctx.deviceNetworkStatus, ifname, proxyLookupURL)
	if err == nil && proxyURL != nil {
		log.Functionf("%s: Using proxy %s", trType, proxyURL.String())
		dEndPoint.WithProxy(proxyURL)
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
