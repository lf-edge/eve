// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedUpload

import (
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/lf-edge/eve-libs/nettrace"
	zedHttp "github.com/lf-edge/eve-libs/zedUpload/httputil"
	"github.com/lf-edge/eve-libs/zedUpload/types"
)

type HttpTransportMethod struct {
	transport SyncTransportType
	hurl      string
	path      string

	authType string

	failPostTime time.Time
	ctx          *DronaCtx
	hClientWrap  *httpClientWrapper
}

// Action : execute selected action targeting HTTP datastore.
func (ep *HttpTransportMethod) Action(req *DronaRequest) error {
	var err error
	var size int
	var list []string
	var contentLength int64

	switch req.operation {
	case SyncOpDownload:
		err, size = ep.processHttpDownload(req)
	case SyncOpUpload:
		err, size = ep.processHttpUpload(req)
	case SyncOpDelete:
		err = ep.processHttpDelete(req)
	case SyncOpList:
		list, err = ep.processHttpList(req)
		req.imgList = list
	case SyncOpGetObjectMetaData:
		err, contentLength = ep.processHttpObjectMetaData(req)
		req.contentLength = contentLength
	case SysOpDownloadByChunks:
		err = fmt.Errorf("Chunk download for HTTP transport is not supported yet")
	default:
		err = fmt.Errorf("Unknown HTTP datastore operation")
	}

	req.asize = int64(size)
	if err != nil {
		req.status = fmt.Sprintf("%v", err)
	}
	return err
}

func (ep *HttpTransportMethod) Open() error {
	return nil
}

func (ep *HttpTransportMethod) Close() error {
	return ep.hClientWrap.close()
}

// WithSrcIP : use the specific IP as source address for this connection.
func (ep *HttpTransportMethod) WithSrcIP(localAddr net.IP) error {
	return ep.hClientWrap.withSrcIP(localAddr)
}

// WithProxy : connect via the provided proxy URL.
func (ep *HttpTransportMethod) WithProxy(proxy *url.URL) error {
	return ep.hClientWrap.withProxy(proxy)
}

// WithTrustedCerts : run requests with these certificates added as trusted.
func (ep *HttpTransportMethod) WithTrustedCerts(certs [][]byte) error {
	return ep.hClientWrap.withTrustedCerts(certs)
}

// WithBindIntf : bind to specific interface for this connection
func (ep *HttpTransportMethod) WithBindIntf(intf string) error {
	return ep.hClientWrap.withBindIntf(intf)
}

// WithLogging enables or disables logging.
func (ep *HttpTransportMethod) WithLogging(onoff bool) error {
	return nil
}

// WithNetTracing enables network tracing.
func (ep *HttpTransportMethod) WithNetTracing(opts ...nettrace.TraceOpt) error {
	return ep.hClientWrap.withNetTracing(opts...)
}

// GetNetTrace returns collected network trace and packet captures.
func (ep *HttpTransportMethod) GetNetTrace(description string) (
	nettrace.AnyNetTrace, []nettrace.PacketCapture, error) {
	return ep.hClientWrap.getNetTrace(description)
}

// File upload to HTTP Datastore
func (ep *HttpTransportMethod) processHttpUpload(req *DronaRequest) (error, int) {
	postUrl := ep.hurl + "/" + ep.path
	prgChan := make(types.StatsNotifChan)
	defer close(prgChan)
	if req.ackback {
		go statsUpdater(req, ep.ctx, prgChan)
	}
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return err, 0
	}
	stats, resp := zedHttp.ExecCmd(req.cancelContext, "post", postUrl, req.name,
		req.objloc, req.sizelimit, prgChan, hClient)
	return stats.Error, resp.BodyLength
}

// File download from HTTP Datastore
func (ep *HttpTransportMethod) processHttpDownload(req *DronaRequest) (error, int) {
	file := req.name
	if ep.hurl != "" {
		file = ep.hurl + "/" + ep.path + "/" + req.name
	}
	prgChan := make(types.StatsNotifChan)
	defer close(prgChan)
	if req.ackback {
		go statsUpdater(req, ep.ctx, prgChan)
	}
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return err, 0
	}
	stats, resp := zedHttp.ExecCmd(req.cancelContext, "get", file, "",
		req.objloc, req.sizelimit, prgChan, hClient)
	return stats.Error, resp.BodyLength
}

// File delete from HTTP Datastore
func (ep *HttpTransportMethod) processHttpDelete(req *DronaRequest) error {
	return nil
}

// File list from HTTP Datastore
func (ep *HttpTransportMethod) processHttpList(req *DronaRequest) ([]string, error) {
	listUrl := ep.hurl + "/" + ep.path
	prgChan := make(types.StatsNotifChan)
	defer close(prgChan)
	if req.ackback {
		go statsUpdater(req, ep.ctx, prgChan)
	}
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return nil, err
	}
	stats, resp := zedHttp.ExecCmd(req.cancelContext, "ls", listUrl, "", "",
		req.sizelimit, prgChan, hClient)
	return resp.List, stats.Error
}

// Object Metadata from HTTP datastore
func (ep *HttpTransportMethod) processHttpObjectMetaData(req *DronaRequest) (error, int64) {
	file := req.name
	if ep.hurl != "" {
		file = ep.hurl + "/" + ep.path + "/" + req.name
	}
	prgChan := make(types.StatsNotifChan)
	defer close(prgChan)
	if req.ackback {
		go statsUpdater(req, ep.ctx, prgChan)
	}
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return err, 0
	}
	stats, resp := zedHttp.ExecCmd(req.cancelContext, "meta", file, "", req.objloc,
		req.sizelimit, prgChan, hClient)
	return stats.Error, resp.ContentLength
}
func (ep *HttpTransportMethod) getContext() *DronaCtx {
	return ep.ctx
}

func (ep *HttpTransportMethod) NewRequest(opType SyncOpType, objname, objloc string,
	sizelimit int64, ackback bool, reply chan *DronaRequest) *DronaRequest {
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
