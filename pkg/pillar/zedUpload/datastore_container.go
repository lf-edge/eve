// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedUpload

import (
	"fmt"
	container "github.com/lf-edge/eve/pkg/pillar/zedUpload/containerutil"
	"net"
	"net/http"
	"net/url"
	"time"
)

type ContainerTransportMethod struct {
	// required : transport type
	transport SyncTransportType

	// required : url/fqdn/ip address to reach
	surl string

	// type of auth
	authType string

	// required, auth for whom
	uname string

	// optional, password
	passwd string

	failPostTime time.Time

	ctx     *DronaCtx
	hClient *http.Client
}

//
//
func (ep *ContainerTransportMethod) Action(req *DronaRequest) error {
	var err error
	var resp string

	switch req.operation {
	case SyncOpDownload:
		resp, err = ep.processContainerDownload(req)
	case SyncOpUpload:
		resp, err = ep.processContainerUpload(req)
	default:
		err = fmt.Errorf("Unknown Container datastore operation")
	}

	if err != nil {
		req.status = fmt.Sprintf("%v", err)
	} else {
		req.message = resp
	}
	return err
}

func (ep *ContainerTransportMethod) Open() error {
	return nil
}

func (ep *ContainerTransportMethod) Close() error {
	return nil
}

// use the specific ip as source address for this connection
func (ep *ContainerTransportMethod) WithSrcIpSelection(localAddr net.IP) error {
	return fmt.Errorf("not supported")
}

func (ep *ContainerTransportMethod) WithSrcIpAndProxySelection(localAddr net.IP,
	proxy *url.URL) error {
	return fmt.Errorf("not supported")
}

// bind to specific interface for this connection
func (ep *ContainerTransportMethod) WithBindIntf(intf string) error {
	return fmt.Errorf("not supported")
}

func (ep *ContainerTransportMethod) WithLogging(onoff bool) error {
	return nil
}

// File upload to Container Registry
func (ep *ContainerTransportMethod) processContainerUpload(req *DronaRequest) (string, error) {
	file := req.name
	resp, err := container.UploadContainerImage(ep.surl, ep.uname, ep.passwd, file, ep.hClient)
	return resp, err
}

// File download from Container Registry
func (ep *ContainerTransportMethod) processContainerDownload(req *DronaRequest) (string, error) {
	file := req.name
	resp, err := container.DownloadContainerImage(ep.surl, ep.uname, ep.passwd, file, ep.hClient)
	return resp, err
}

func (ep *ContainerTransportMethod) getContext() *DronaCtx {
	return ep.ctx
}

func (ep *ContainerTransportMethod) NewRequest(opType SyncOpType, objname, objloc string, sizelimit int64, ackback bool, reply chan *DronaRequest) *DronaRequest {
	dR := &DronaRequest{}
	dR.syncEp = ep
	dR.operation = opType
	dR.name = objname
	dR.objloc = objloc
	dR.ackback = ackback

	// FIXME:...we need this later
	dR.localName = objname

	// limit for this download
	dR.sizelimit = sizelimit
	dR.result = reply

	return dR
}
