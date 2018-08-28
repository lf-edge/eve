package zedUpload

import (
	"fmt"
	"github.com/zededa/shared/srvs/drona/sftp"
	"log"
	"net"
	"strings"
	"time"
)

const (
	StatsUpdateTicker = 20 * time.Second // timer for updating client for stats
	FailPostTimeout   = 2 * time.Minute
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

	switch req.operation {
	case SyncOpUpload:
		err, size = ep.processSftpUpload(req)
	case SyncOpDownload:
		err, size = ep.processSftpDownload(req)
	case SyncOpDelete:
		err = ep.processSftpDelete(req)
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

// use the specific ip as source address for this connection
func (ep *SftpTransportMethod) WithSrcIpSelection(localAddr net.IP) error {
	return fmt.Errorf("not supported")
}

// bind to specific interface for this connection
func (ep *SftpTransportMethod) WithBindIntf(intf string) error {
	return fmt.Errorf("not supported")
}

func (ep *SftpTransportMethod) WithLogging(onoff bool) error {
	return nil
}

func (ep *SftpTransportMethod) processSftpDownload(req *DronaRequest) (error, int) {
	file := req.name
	if ep.path != "" {
		if strings.HasSuffix(ep.path, "/") {
			file = ep.path + req.name
		} else {
			file = ep.path + "/" + req.name
		}
	}
	log.Printf("Started Downloading enterprise image %s to %s, ep %v", req.objloc, file, ep.surl)
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

	size, err := sftp.ExecCmd("fetch", ep.surl, ep.uname, ep.passwd, file, req.objloc, prgChan)
	if err != nil {
		return err, int(size)
	}
	log.Printf("Successfully downloaded enterprise image %s to %s", req.objloc, file)
	return err, int(size)
}

func (ep *SftpTransportMethod) processSftpUpload(req *DronaRequest) (error, int) {
	file := req.name
	if ep.path != "" {
		if strings.HasSuffix(ep.path, "/") {
			file = ep.path + req.name
		} else {
			file = ep.path + "/" + req.name
		}
	}
	log.Printf("Started Uploading enterprise image %s to %s, ep %v", req.objloc, file, ep.surl)
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

	size, err := sftp.ExecCmd("put", ep.surl, ep.uname, ep.passwd, file, req.objloc, prgChan)
	if err != nil {
		return err, int(size)
	}
	log.Printf("Successfully uploaded enterprise image %s to %s", req.objloc, file)
	return err, int(size)
}

func (ep *SftpTransportMethod) processSftpDelete(req *DronaRequest) error {
	file := req.name
	if ep.path != "" {
		if strings.HasSuffix(ep.path, "/") {
			file = ep.path + req.name
		} else {
			file = ep.path + "/" + req.name
		}
	}
	_, err := sftp.ExecCmd("rm", ep.surl, ep.uname, ep.passwd, file, "", nil)
	if err != nil {
		return err
	}
	log.Printf("Successfully deleted enterprise image %s ", file)
	return nil
}

func (ep *SftpTransportMethod) getContext() *DronaCtx {
	return ep.ctx
}

func (ep *SftpTransportMethod) NewRequest(opType SyncOpType, objname, objloc string, sizelimit int64, ackback bool, reply chan *DronaRequest) *DronaRequest {
	dR := &DronaRequest{}
	dR.syncEp = ep
	dR.operation = opType
	dR.name = objname

	// FIXME:...we need this later
	dR.localName = objname
	dR.objloc = objloc

	// limit for this download
	dR.sizelimit = sizelimit
	dR.result = reply

	return dR
}
