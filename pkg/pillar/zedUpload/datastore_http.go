// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedUpload

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	zedHttp "github.com/lf-edge/eve/pkg/pillar/zedUpload/httputil"
)

type HttpTransportMethod struct {
	transport SyncTransportType
	hurl      string
	path      string

	authType string

	failPostTime time.Time
	ctx          *DronaCtx
	hClient      *http.Client
}

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
	return nil
}

// WithSrcIPSelection use the specific ip as source address for this connection
func (ep *HttpTransportMethod) WithSrcIPSelection(localAddr net.IP) error {
	ep.hClient = httpClientSrcIP(localAddr, nil)
	return nil
}

// WithSrcIPAndProxySelection use the specific ip as source address for this
// connection and connect via the provided proxy URL
func (ep *HttpTransportMethod) WithSrcIPAndProxySelection(localAddr net.IP,
	proxy *url.URL) error {
	ep.hClient = httpClientSrcIP(localAddr, proxy)
	return nil
}

// bind to specific interface for this connection
func (ep *HttpTransportMethod) WithBindIntf(intf string) error {
	return fmt.Errorf("not supported")
}

func (ep *HttpTransportMethod) WithLogging(onoff bool) error {
	return nil
}

// File upload to HTTP Datastore
func (ep *HttpTransportMethod) processHttpUpload(req *DronaRequest) (error, int) {
	postUrl := ep.hurl + "/" + ep.path
	prgChan := make(zedHttp.NotifChan)
	defer close(prgChan)
	if req.ackback {
		go func(req *DronaRequest, prgNotif zedHttp.NotifChan) {
			ticker := time.NewTicker(StatsUpdateTicker)
			var stats zedHttp.UpdateStats
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
	resp := zedHttp.ExecCmd("post", postUrl, req.name, req.objloc, req.sizelimit, prgChan, ep.hClient)
	return resp.Error, resp.BodyLength
}

// File download from HTTP Datastore
func (ep *HttpTransportMethod) processHttpDownload(req *DronaRequest) (error, int) {
	file := req.name
	if ep.hurl != "" {
		file = ep.hurl + "/" + ep.path + "/" + req.name
	}
	prgChan := make(zedHttp.NotifChan)
	defer close(prgChan)
	if req.ackback {
		go func(req *DronaRequest, prgNotif zedHttp.NotifChan) {
			ticker := time.NewTicker(StatsUpdateTicker)
			var stats zedHttp.UpdateStats
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
	resp := zedHttp.ExecCmd("get", file, "", req.objloc, req.sizelimit, prgChan, ep.hClient)
	if resp.Error != nil {
		return resp.Error, resp.BodyLength
	}
	return resp.Error, resp.BodyLength
}

// File delete from HTTP Datastore
func (ep *HttpTransportMethod) processHttpDelete(req *DronaRequest) error {
	return nil
}

// File list from HTTP Datastore
func (ep *HttpTransportMethod) processHttpList(req *DronaRequest) ([]string, error) {
	listUrl := ep.hurl + "/" + ep.path
	prgChan := make(zedHttp.NotifChan)
	defer close(prgChan)
	if req.ackback {
		go func(req *DronaRequest, prgNotif zedHttp.NotifChan) {
			ticker := time.NewTicker(StatsUpdateTicker)
			var stats zedHttp.UpdateStats
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
	resp := zedHttp.ExecCmd("ls", listUrl, "", "", req.sizelimit, prgChan, ep.hClient)
	return resp.List, resp.Error
}

// Object Metadata from HTTP datastore
func (ep *HttpTransportMethod) processHttpObjectMetaData(req *DronaRequest) (error, int64) {
	file := req.name
	if ep.hurl != "" {
		file = ep.hurl + "/" + ep.path + "/" + req.name
	}
	prgChan := make(zedHttp.NotifChan)
	defer close(prgChan)
	if req.ackback {
		go func(req *DronaRequest, prgNotif zedHttp.NotifChan) {
			ticker := time.NewTicker(StatsUpdateTicker)
			var stats zedHttp.UpdateStats
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
	resp := zedHttp.ExecCmd("meta", file, "", req.objloc, req.sizelimit, prgChan, ep.hClient)
	if resp.Error != nil {
		return resp.Error, resp.ContentLength
	}
	return resp.Error, resp.ContentLength
}
func (ep *HttpTransportMethod) getContext() *DronaCtx {
	return ep.ctx
}

func (ep *HttpTransportMethod) NewRequest(opType SyncOpType, objname, objloc string, sizelimit int64, ackback bool, reply chan *DronaRequest) *DronaRequest {
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
