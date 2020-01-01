// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedUpload

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/zedUpload/sftputil"
	"net"
	"net/url"
	"strings"
	"time"
)

type SftpTransportMethod struct {
	// required : transport type
	transport SyncTransportType

	// required : url/fqdn/ip address to reach
	surl string

	// optional : web path, or bucket etc defaults to /
	path string

	// type of auth
	authType string

	// required, auth for whom
	uname string

	// optional, password
	passwd string

	// optional, keytabs
	keys []string

	// optional hosttabs
	htab []byte

	failPostTime time.Time

	ctx *DronaCtx
}

//
//
func (ep *SftpTransportMethod) Action(req *DronaRequest) error {
	var err error
	var size int
	var list []string
	var contentLength int64

	switch req.operation {
	case SyncOpUpload:
		err, size = ep.processSftpUpload(req)
	case SyncOpDownload:
		err, size = ep.processSftpDownload(req)
	case SyncOpDelete:
		err = ep.processSftpDelete(req)
	case SyncOpList:
		list, err = ep.processSftpList(req)
		req.imgList = list
	case SyncOpGetObjectMetaData:
		err, contentLength = ep.processSftpObjectMetaData(req)
		req.contentLength = contentLength
	default:
		err = fmt.Errorf("Unknown SFTP datastore operation")
	}

	req.asize = int64(size)
	if err != nil {
		req.status = fmt.Sprintf("%v", err)
	}
	return err
}

func (ep *SftpTransportMethod) Open() error {
	return nil
}

func (ep *SftpTransportMethod) Close() error {
	return nil
}

// WithSrcIPSelection use the specific ip as source address for this connection
func (ep *SftpTransportMethod) WithSrcIPSelection(localAddr net.IP) error {
	return fmt.Errorf("not supported")
}

// WithSrcIPAndProxySelection use the specific ip as source address for this
// connection and connect via the provided proxy URL
func (ep *SftpTransportMethod) WithSrcIPAndProxySelection(localAddr net.IP,
	proxy *url.URL) error {
	return fmt.Errorf("not supported")
}

// bind to specific interface for this connection
func (ep *SftpTransportMethod) WithBindIntf(intf string) error {
	return fmt.Errorf("not supported")
}

func (ep *SftpTransportMethod) WithLogging(onoff bool) error {
	return nil
}

// File upload to SFTP Datastore
func (ep *SftpTransportMethod) processSftpUpload(req *DronaRequest) (error, int) {
	file := req.name
	if ep.path != "" {
		if strings.HasSuffix(ep.path, "/") {
			file = ep.path + req.name
		} else {
			file = ep.path + "/" + req.name
		}
	}
	prgChan := make(sftp.NotifChan)
	defer close(prgChan)
	if req.ackback {
		go func(req *DronaRequest, prgNotif sftp.NotifChan) {
			ticker := time.NewTicker(StatsUpdateTicker)
			var stats sftp.UpdateStats
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

	resp := sftp.ExecCmd("put", ep.surl, ep.uname, ep.passwd, file, req.objloc, prgChan)
	return resp.Error, int(resp.Asize)
}

// File download from SFTP Datastore
func (ep *SftpTransportMethod) processSftpDownload(req *DronaRequest) (error, int) {
	file := req.name
	if ep.path != "" {
		if strings.HasSuffix(ep.path, "/") {
			file = ep.path + req.name
		} else {
			file = ep.path + "/" + req.name
		}
	}
	prgChan := make(sftp.NotifChan)
	defer close(prgChan)
	if req.ackback {
		go func(req *DronaRequest, prgNotif sftp.NotifChan) {
			ticker := time.NewTicker(StatsUpdateTicker)
			var stats sftp.UpdateStats
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

	resp := sftp.ExecCmd("fetch", ep.surl, ep.uname, ep.passwd, file, req.objloc, prgChan)
	return resp.Error, int(resp.Asize)
}

// File delete from SFTP Datastore
func (ep *SftpTransportMethod) processSftpDelete(req *DronaRequest) error {
	file := req.name
	if ep.path != "" {
		if strings.HasSuffix(ep.path, "/") {
			file = ep.path + req.name
		} else {
			file = ep.path + "/" + req.name
		}
	}
	resp := sftp.ExecCmd("rm", ep.surl, ep.uname, ep.passwd, file, "", nil)
	return resp.Error
}

// File list from SFTP Datastore
func (ep *SftpTransportMethod) processSftpList(req *DronaRequest) ([]string, error) {
	prgChan := make(sftp.NotifChan)
	defer close(prgChan)
	if req.ackback {
		go func(req *DronaRequest, prgNotif sftp.NotifChan) {
			ticker := time.NewTicker(StatsUpdateTicker)
			var stats sftp.UpdateStats
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

	resp := sftp.ExecCmd("ls", ep.surl, ep.uname, ep.passwd, ep.path, "", prgChan)
	return resp.List, resp.Error
}

func (ep *SftpTransportMethod) processSftpObjectMetaData(req *DronaRequest) (error, int64) {
	file := req.name
	if ep.path != "" {
		if strings.HasSuffix(ep.path, "/") {
			file = ep.path + req.name
		} else {
			file = ep.path + "/" + req.name
		}
	}
	resp := sftp.ExecCmd("stat", ep.surl, ep.uname, ep.passwd, file, "", nil)
	return resp.Error, resp.ContentLength
}

func (ep *SftpTransportMethod) getContext() *DronaCtx {
	return ep.ctx
}

func (ep *SftpTransportMethod) NewRequest(opType SyncOpType, objname, objloc string, sizelimit int64, ackback bool, reply chan *DronaRequest) *DronaRequest {
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
