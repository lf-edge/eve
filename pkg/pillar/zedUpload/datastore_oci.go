// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedUpload

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	ociutil "github.com/lf-edge/eve/pkg/pillar/zedUpload/ociutil"
)

// OCITransportMethod transport method to send images from OCI distribution
// registries
type OCITransportMethod struct {
	transport SyncTransportType
	registry  string
	path      string

	// optional, auth username and api key
	uname  string
	apiKey string

	failPostTime time.Time
	ctx          *DronaCtx
	hClient      *http.Client
}

// Action perform an action using this method, one of
// Download/Upload/Delete/List/GetObjectMetaData
func (ep *OCITransportMethod) Action(req *DronaRequest) error {
	var err error
	var size int64
	var list []string
	var contentLength int64
	var sha256, contentType string

	switch req.operation {
	case SyncOpDownload:
		size, contentType, err = ep.processDownload(req)
		req.contentType = contentType
	case SyncOpUpload:
		size, err = ep.processUpload(req)
	case SyncOpDelete:
		err = ep.processDelete(req)
	case SyncOpList:
		list, err = ep.processList(req)
		req.imgList = list
	case SyncOpGetObjectMetaData:
		sha256, contentLength, err = ep.processObjectMetaData(req)
		req.contentLength = contentLength
		req.ImageSha256 = sha256
	case SysOpDownloadByChunks:
		err = fmt.Errorf("Chunk download for OCI tansport is not supported yet")
	default:
		err = fmt.Errorf("Unknown OCI registry operation")
	}

	req.asize = size
	if err != nil {
		req.status = fmt.Sprintf("%v", err)
	}
	return err
}

// Open unsupported
func (ep *OCITransportMethod) Open() error {
	return nil
}

// Close unsupported
func (ep *OCITransportMethod) Close() error {
	return nil
}

// WithSrcIPSelection use the specific ip as source address for this connection
func (ep *OCITransportMethod) WithSrcIPSelection(localAddr net.IP) error {
	ep.hClient = httpClientSrcIP(localAddr, nil)
	return nil
}

// WithSrcIPAndProxySelection use the specific ip as source address for this
// connection and transit through the specific proxy URL
func (ep *OCITransportMethod) WithSrcIPAndProxySelection(localAddr net.IP,
	proxy *url.URL) error {
	ep.hClient = httpClientSrcIP(localAddr, proxy)
	return nil
}

// WithBindIntf bind to specific interface for this connection
func (ep *OCITransportMethod) WithBindIntf(intf string) error {
	localAddr := getSrcIpFromInterface(intf)
	if localAddr == nil {
		return fmt.Errorf("failed to get the address for intf")
	}
	ep.hClient = httpClientSrcIP(localAddr, nil)
	return nil
}

// WithLogging enable logging, not yet supported
func (ep *OCITransportMethod) WithLogging(onoff bool) error {
	return nil
}

// processUpload artifact upload to OCI registry
// not yet supported
func (ep *OCITransportMethod) processUpload(req *DronaRequest) (int64, error) {
	return 0, fmt.Errorf("unsupported")
}

// processDownload Artifact download from OCI registry
func (ep *OCITransportMethod) processDownload(req *DronaRequest) (int64, string, error) {
	var (
		err         error
		size        int64
		contentType string
	)
	if ep.registry == "" {
		return size, "", fmt.Errorf("cannot download from blank registry")
	}
	prgChan := make(ociutil.NotifChan)
	defer close(prgChan)
	if req.ackback {
		go func(req *DronaRequest, prgNotif ociutil.NotifChan) {
			ticker := time.NewTicker(StatsUpdateTicker)
			var stats ociutil.UpdateStats
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

	// Pull down the blob as is and save it to a file named for the hash
	size, contentType, err = ociutil.PullBlob(ep.registry, ep.path, req.ImageSha256, req.objloc, ep.uname, ep.apiKey, req.sizelimit, ep.hClient, prgChan)
	// zedUpload's job is to download a blob from an OCI registry. Done.
	return size, contentType, err
}

// processDelete Artifact delete from OCI registry
func (ep *OCITransportMethod) processDelete(req *DronaRequest) error {
	return nil
}

// processList list tags for a given image in OCI registry
func (ep *OCITransportMethod) processList(req *DronaRequest) ([]string, error) {
	prgChan := make(ociutil.NotifChan)
	defer close(prgChan)
	if req.ackback {
		go func(req *DronaRequest, prgNotif ociutil.NotifChan) {
			ticker := time.NewTicker(StatsUpdateTicker)
			var stats ociutil.UpdateStats
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
	return ociutil.Tags(ep.registry, ep.path, ep.uname, ep.apiKey, ep.hClient, prgChan)
}

// processObjectMetaData Artifact Metadata from OCI registry
func (ep *OCITransportMethod) processObjectMetaData(req *DronaRequest) (string, int64, error) {
	var (
		err           error
		size          int64
		imageSha256   string
		imageManifest []byte
	)
	if ep.registry == "" {
		return imageSha256, size, fmt.Errorf("cannot download from blank registry")
	}
	prgChan := make(ociutil.NotifChan)
	defer close(prgChan)
	if req.ackback {
		go func(req *DronaRequest, prgNotif ociutil.NotifChan) {
			ticker := time.NewTicker(StatsUpdateTicker)
			var stats ociutil.UpdateStats
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
	_, imageManifest, size, err = ociutil.Manifest(ep.registry, ep.path, ep.uname, ep.apiKey, ep.hClient, prgChan)
	if err != nil {
		return imageSha256, 0, err
	}
	hash := sha256.Sum256(imageManifest)
	imageSha256 = strings.ToUpper(fmt.Sprintf("%x", hash))
	return imageSha256, size, nil
}

func (ep *OCITransportMethod) getContext() *DronaCtx {
	return ep.ctx
}

// NewRequest create a new DronaRequest with this OCITransportMethod as the endpoint
func (ep *OCITransportMethod) NewRequest(opType SyncOpType, objname, objloc string, sizelimit int64, ackback bool, reply chan *DronaRequest) *DronaRequest {
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
