// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedUpload

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/lf-edge/eve/libs/nettrace"
	sftp "github.com/lf-edge/eve/libs/zedUpload/sftputil"
	"github.com/lf-edge/eve/libs/zedUpload/types"
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

	failPostTime time.Time

	ctx *DronaCtx
}

// Action : execute selected action targeting SFTP datastore.
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
	case SysOpDownloadByChunks:
		err = fmt.Errorf("Chunk download for SFTP transport is not supported yet")
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

// WithSrcIP is not supported.
func (ep *SftpTransportMethod) WithSrcIP(localAddr net.IP) error {
	return fmt.Errorf("not supported")
}

// WithProxy is not supported.
func (ep *SftpTransportMethod) WithProxy(proxy *url.URL) error {
	return fmt.Errorf("not supported")
}

// WithTrustedCerts is not supported.
func (ep *SftpTransportMethod) WithTrustedCerts(certs [][]byte) error {
	return fmt.Errorf("not supported")
}

// WithBindIntf is not supported.
func (ep *SftpTransportMethod) WithBindIntf(intf string) error {
	return fmt.Errorf("not supported")
}

// WithLogging enables or disables logging.
func (ep *SftpTransportMethod) WithLogging(onoff bool) error {
	return nil
}

// WithNetTracing is not supported.
func (ep *SftpTransportMethod) WithNetTracing(opts ...nettrace.TraceOpt) error {
	return fmt.Errorf("not supported")
}

// GetNetTrace is not supported.
func (ep *SftpTransportMethod) GetNetTrace(description string) (
	nettrace.AnyNetTrace, []nettrace.PacketCapture, error) {
	return nil, nil, fmt.Errorf("not supported")
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
	prgChan := make(types.StatsNotifChan)
	defer close(prgChan)
	if req.ackback {
		go statsUpdater(req, ep.ctx, prgChan)
	}

	stats, _ := sftp.ExecCmd("put", ep.surl, ep.uname, ep.passwd, file, req.objloc, req.sizelimit, prgChan)
	return stats.Error, int(stats.Asize)
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
	prgChan := make(types.StatsNotifChan)
	defer close(prgChan)
	if req.ackback {
		go statsUpdater(req, ep.ctx, prgChan)
	}

	stats, _ := sftp.ExecCmd("fetch", ep.surl, ep.uname, ep.passwd, file, req.objloc, req.sizelimit, prgChan)
	return stats.Error, int(stats.Asize)
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
	stats, _ := sftp.ExecCmd("rm", ep.surl, ep.uname, ep.passwd, file, "", req.sizelimit, nil)
	return stats.Error
}

// File list from SFTP Datastore
func (ep *SftpTransportMethod) processSftpList(req *DronaRequest) ([]string, error) {
	prgChan := make(types.StatsNotifChan)
	defer close(prgChan)
	if req.ackback {
		go statsUpdater(req, ep.ctx, prgChan)
	}

	stats, resp := sftp.ExecCmd("ls", ep.surl, ep.uname, ep.passwd, ep.path, "", req.sizelimit, prgChan)
	return resp.List, stats.Error
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
	stats, resp := sftp.ExecCmd("stat", ep.surl, ep.uname, ep.passwd, file, "", req.sizelimit, nil)
	return stats.Error, resp.ContentLength
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
