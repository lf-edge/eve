// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedUpload

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/lf-edge/eve/libs/nettrace"
	zedGS "github.com/lf-edge/eve/libs/zedUpload/gsutil"
	"github.com/lf-edge/eve/libs/zedUpload/types"
)

// Action do the operation with Google Storage datastore
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

// Open not implemented
func (ep *GsTransportMethod) Open() error {
	return nil
}

// Close not implemented
func (ep *GsTransportMethod) Close() error {
	return ep.hClientWrap.close()
}

// WithSrcIP : use the specific IP as source address for this connection.
func (ep *GsTransportMethod) WithSrcIP(localAddr net.IP) error {
	return ep.hClientWrap.withSrcIP(localAddr)
}

// WithProxy : connect via the provided proxy URL.
func (ep *GsTransportMethod) WithProxy(proxy *url.URL) error {
	return ep.hClientWrap.withProxy(proxy)
}

// WithTrustedCerts : run requests with these certificates added as trusted.
func (ep *GsTransportMethod) WithTrustedCerts(certs [][]byte) error {
	return ep.hClientWrap.withTrustedCerts(certs)
}

// WithBindIntf : bind to specific interface for this connection
func (ep *GsTransportMethod) WithBindIntf(intf string) error {
	return ep.hClientWrap.withBindIntf(intf)
}

// WithLogging enables or disables logging.
func (ep *GsTransportMethod) WithLogging(onoff bool) error {
	return nil
}

// WithNetTracing enables network tracing.
func (ep *GsTransportMethod) WithNetTracing(opts ...nettrace.TraceOpt) error {
	return ep.hClientWrap.withNetTracing(opts...)
}

// GetNetTrace returns collected network trace and packet captures.
func (ep *GsTransportMethod) GetNetTrace(description string) (
	nettrace.AnyNetTrace, []nettrace.PacketCapture, error) {
	return ep.hClientWrap.getNetTrace(description)
}

// File upload to Google Storage Datastore
func (ep *GsTransportMethod) processGSUpload(req *DronaRequest) (int, error) {
	fInfo, err := os.Stat(req.objloc)
	if err != nil {
		return 0, err
	}
	prgChan := make(types.StatsNotifChan)
	defer close(prgChan)
	if req.ackback {
		go statsUpdater(req, ep.ctx, prgChan)
	}
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return 0, err
	}

	sc, err := zedGS.NewGsCtx(req.cancelContext, ep.projectID, ep.apiKey, hClient, true)
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
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return 0, err
	}
	s, err := zedGS.NewGsCtx(req.cancelContext, ep.projectID, ep.apiKey, hClient, false)
	if err != nil {
		return 0, err
	}
	if req.ackback {
		length, err := s.GetObjectSize(ep.bucket, req.name)
		if err == nil {
			ep.ctx.postSize(req, length, 0)
		}
	}

	prgChan := make(types.StatsNotifChan)
	defer close(prgChan)
	if req.ackback {
		go statsUpdater(req, ep.ctx, prgChan)
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
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return err
	}
	gsctx, err := zedGS.NewGsCtx(req.cancelContext, ep.projectID, ep.apiKey, hClient, true)
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

	prgChan := make(types.StatsNotifChan)
	defer close(prgChan)
	if req.ackback {
		go statsUpdater(req, ep.ctx, prgChan)
	}
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return s, 0, err
	}
	sc, err := zedGS.NewGsCtx(req.cancelContext, ep.projectID, ep.apiKey, hClient, false)
	if err != nil {
		return s, 0, err
	}

	list, err := sc.ListImages(ep.bucket, prgChan)
	if err != nil {
		return s, 0, err
	}

	return list, csize, err
}

// Verify Uploaded Object Size and MD5 sum
func (ep *GsTransportMethod) processGSObjectMetaData(req *DronaRequest) (int64, string, error) {
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return 0, "", err
	}
	sc, err := zedGS.NewGsCtx(req.cancelContext, ep.projectID, ep.apiKey, hClient, false)
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

// NewRequest returns DronaRequest for provided options
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

// GsTransportMethod stores data needed to communicate with Google Cloud Storage
type GsTransportMethod struct {
	transport SyncTransportType
	projectID string
	bucket    string

	//Auth
	apiKey string

	failPostTime time.Time
	ctx          *DronaCtx
	hClientWrap  *httpClientWrapper
}
