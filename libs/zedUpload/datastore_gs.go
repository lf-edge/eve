// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedUpload

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	zedGS "github.com/lf-edge/eve/libs/zedUpload/gsutil"
)

//Action do the operation with Google Storage datastore
func (ep *GsTransportMethod) Action(req *DronaRequest) error {
	var err error
	var size int
	var list []string
	var contentLength int64
	var remoteFileMD5 string

	switch req.operation {
	case SyncOpUpload:
		size, err = ep.processGSUpload(req)
	case SyncOpDownload:
		size, err = ep.processGSDownload(req)
	case SyncOpDelete:
		err = ep.processGSDelete(req)
	case SyncOpList:
		list, size, err = ep.processGSList(req)
		req.imgList = list
	case SyncOpGetObjectMetaData:
		contentLength, remoteFileMD5, err = ep.processGSObjectMetaData(req)
		req.contentLength = contentLength
		req.remoteFileMD5 = remoteFileMD5
	case SysOpPutPart:
		err = fmt.Errorf("part upload for GS transport is not supported yet")
	case SysOpCompleteParts:
		err = fmt.Errorf("part upload for GS transport is not supported yet")
	case SyncOpGetURI:
		err = fmt.Errorf("signed url for GS transport is not supported yet")
	case SysOpDownloadByChunks:
		err = fmt.Errorf("chunk download for GS transport is not supported yet")
	default:
		err = fmt.Errorf("unknown Google Storage datastore operation")
	}

	req.asize = int64(size)
	if err != nil {
		req.status = fmt.Sprintf("%v", err)
	}

	return err
}

//Open not implemented
func (ep *GsTransportMethod) Open() error {
	return nil
}

//Close not implemented
func (ep *GsTransportMethod) Close() error {
	return nil
}

// WithSrcIPSelection use the specific ip as source address for this connection
func (ep *GsTransportMethod) WithSrcIPSelection(localAddr net.IP) error {
	ep.hClient = httpClientSrcIP(localAddr, nil)
	return nil
}

// WithSrcIPAndProxySelection use the specific ip as source address for this
// connection and connect via the provided proxy URL
func (ep *GsTransportMethod) WithSrcIPAndProxySelection(localAddr net.IP,
	proxy *url.URL) error {
	ep.hClient = httpClientSrcIP(localAddr, proxy)
	return nil
}

// WithSrcIPAndHTTPSCerts append certs for the datastore access
func (ep *GsTransportMethod) WithSrcIPAndHTTPSCerts(localAddr net.IP, certs [][]byte) error {
	client := httpClientSrcIP(localAddr, nil)
	client, err := httpClientAddCerts(client, certs)
	if err != nil {
		return err
	}
	ep.hClient = client
	return nil
}

// WithSrcIPAndProxyAndHTTPSCerts takes a proxy and proxy certs
func (ep *GsTransportMethod) WithSrcIPAndProxyAndHTTPSCerts(localAddr net.IP, proxy *url.URL, certs [][]byte) error {
	client := httpClientSrcIP(localAddr, proxy)
	client, err := httpClientAddCerts(client, certs)
	if err != nil {
		return err
	}
	ep.hClient = client
	return nil
}

//WithBindIntf bind to specific interface for this connection
func (ep *GsTransportMethod) WithBindIntf(intf string) error {
	localAddr := getSrcIpFromInterface(intf)
	if localAddr != nil {
		ep.hClient = httpClientSrcIP(localAddr, nil)
		return nil
	}
	return fmt.Errorf("failed to get the address for intf")
}

//WithLogging enables logging
func (ep *GsTransportMethod) WithLogging(onoff bool) error {
	return nil
}

// File upload to Google Storage Datastore
func (ep *GsTransportMethod) processGSUpload(req *DronaRequest) (int, error) {
	fInfo, err := os.Stat(req.objloc)
	if err != nil {
		return 0, err
	}
	prgChan := make(zedGS.NotifChan)
	defer close(prgChan)
	if req.ackback {
		go func(req *DronaRequest, prgNotif zedGS.NotifChan) {
			ticker := time.NewTicker(StatsUpdateTicker)
			defer ticker.Stop()
			var stats zedGS.UpdateStats
			var ok bool
			for {
				select {
				case stats, ok = <-prgNotif:
					if !ok {
						return
					}
				case <-ticker.C:
					ep.ctx.postSize(req, stats.Size, stats.Asize)
				}
			}
		}(req, prgChan)
	}

	sc, err := zedGS.NewGsCtx(req.cancelContext, ep.projectID, ep.apiKey, ep.hClient, true)
	if err != nil {
		return 0, err
	}

	location, err := sc.UploadFile(req.objloc, ep.bucket, req.name, false, prgChan)
	if len(location) > 0 {
		req.objloc = location
	}

	return int(fInfo.Size()), err
}

// File download from Google Storage Datastore
func (ep *GsTransportMethod) processGSDownload(req *DronaRequest) (int, error) {
	var csize int
	s, err := zedGS.NewGsCtx(req.cancelContext, ep.projectID, ep.apiKey, ep.hClient, false)
	if err != nil {
		return 0, err
	}
	if req.ackback {
		length, err := s.GetObjectSize(ep.bucket, req.name)
		if err == nil {
			ep.ctx.postSize(req, length, 0)
		}
	}

	prgChan := make(zedGS.NotifChan)
	defer close(prgChan)
	if req.ackback {
		go func(req *DronaRequest, prgNotif zedGS.NotifChan) {
			ticker := time.NewTicker(StatsUpdateTicker)
			defer ticker.Stop()
			var stats zedGS.UpdateStats
			var ok bool
			for {
				select {
				case stats, ok = <-prgNotif:
					if !ok {
						return
					}
				case <-ticker.C:
					ep.ctx.postSize(req, stats.Size, stats.Asize)
				}
			}
		}(req, prgChan)
	}

	err = s.DownloadFile(req.objloc, ep.bucket, req.name, req.sizelimit, prgChan)
	if err != nil {
		return 0, err
	}
	// check for download complete
	st, err := os.Stat(req.objloc)
	if err != nil {
		return 0, err
	}
	csize = int(st.Size())

	return csize, err
}

// File delete from Google Storage Datastore
func (ep *GsTransportMethod) processGSDelete(req *DronaRequest) error {
	var err error
	gsctx, err := zedGS.NewGsCtx(req.cancelContext, ep.projectID, ep.apiKey, ep.hClient, true)
	if err != nil {
		return err
	}
	err = gsctx.DeleteObject(ep.bucket, req.name)
	if err != nil {
		return err
	}

	return err
}

// File list from Google Storage Datastore
func (ep *GsTransportMethod) processGSList(req *DronaRequest) ([]string, int, error) {
	var csize int
	var s []string

	prgChan := make(zedGS.NotifChan)
	defer close(prgChan)
	if req.ackback {
		go func(req *DronaRequest, prgNotif zedGS.NotifChan) {
			ticker := time.NewTicker(StatsUpdateTicker)
			defer ticker.Stop()
			var stats zedGS.UpdateStats
			var ok bool
			for {
				select {
				case stats, ok = <-prgNotif:
					if !ok {
						return
					}
				case <-ticker.C:
					ep.ctx.postSize(req, stats.Size, stats.Asize)
				}
			}
		}(req, prgChan)
	}
	sc, err := zedGS.NewGsCtx(req.cancelContext, ep.projectID, ep.apiKey, ep.hClient, false)
	if err != nil {
		return s, 0, err
	}

	list, err := sc.ListImages(ep.bucket, prgChan)
	if err != nil {
		return s, 0, err
	}

	return list, csize, err
}

//Verify Uploaded Object Size and MD5 sum
func (ep *GsTransportMethod) processGSObjectMetaData(req *DronaRequest) (int64, string, error) {
	sc, err := zedGS.NewGsCtx(req.cancelContext, ep.projectID, ep.apiKey, ep.hClient, false)
	if err != nil {
		return 0, "", err
	}

	size, remoteFileMD5, err := sc.GetObjectMetaData(ep.bucket, req.name)
	if len(remoteFileMD5) > 0 && remoteFileMD5[0] == '"' {
		remoteFileMD5 = remoteFileMD5[1:]
	}
	if len(remoteFileMD5) > 0 && remoteFileMD5[len(remoteFileMD5)-1] == '"' {
		remoteFileMD5 = remoteFileMD5[:len(remoteFileMD5)-1]
	}
	return size, remoteFileMD5, err
}

//NewRequest returns DronaRequest for provided options
func (ep *GsTransportMethod) NewRequest(opType SyncOpType, objname, objloc string, sizelimit int64, ackback bool, reply chan *DronaRequest) *DronaRequest {
	dR := &DronaRequest{}
	dR.syncEp = ep
	dR.operation = opType
	dR.name = objname
	dR.ackback = ackback

	// FIXME:...we need this later
	dR.localName = objname
	dR.objloc = objloc

	// limit for this download
	dR.sizelimit = sizelimit
	dR.result = reply

	return dR
}

func (ep *GsTransportMethod) getContext() *DronaCtx {
	return ep.ctx
}

//GsTransportMethod stores data needed to communicate with Google Cloud Storage
type GsTransportMethod struct {
	transport SyncTransportType
	projectID string
	bucket    string

	//Auth
	apiKey string

	failPostTime time.Time
	ctx          *DronaCtx
	hClient      *http.Client
}
