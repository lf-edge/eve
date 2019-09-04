// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedUpload

import (
	"fmt"
	azure "github.com/lf-edge/eve/pkg/pillar/zedUpload/azureutil"
	"net"
	"net/http"
	"net/url"
	//	"strings"
	"time"
)

func (ep *AzureTransportMethod) Action(req *DronaRequest) error {
	var err error
	var size int
	var list []string
	var contentLength int64
	var remoteFileMD5 string

	switch req.operation {
	case SyncOpDownload:
		err = ep.processAzureDownload(req)
	case SyncOpUpload:
		err = ep.processAzureUpload(req)
	case SyncOpDelete:
		err = ep.processAzureBlobDelete(req)
	case SyncOpList:
		list, err, size = ep.processAzureBlobList(req)
		req.imgList = list
	case SyncOpGetObjectMetaData:
		contentLength, remoteFileMD5, err = ep.processAzureBlobMetaData(req)
		req.contentLength = contentLength
		req.remoteFileMD5 = remoteFileMD5
	default:
		err = fmt.Errorf("Unknown Azure Blob datastore operation")
	}

	req.asize = int64(size)
	if err != nil {
		req.status = fmt.Sprintf("%v", err)
	}
	return err
}

func (ep *AzureTransportMethod) Open() error {
	return nil
}

func (ep *AzureTransportMethod) Close() error {
	return nil
}

// use the specific ip as source address for this connection
func (ep *AzureTransportMethod) WithSrcIpSelection(localAddr net.IP) error {
	ep.hClient = httpClientSrcIP(localAddr, nil)
	return nil
}

func (ep *AzureTransportMethod) WithSrcIpAndProxySelection(localAddr net.IP,
	proxy *url.URL) error {
	ep.hClient = httpClientSrcIP(localAddr, proxy)
	return nil
}

// bind to specific interface for this connection
func (ep *AzureTransportMethod) WithBindIntf(intf string) error {
	return fmt.Errorf("not supported")
}

func (ep *AzureTransportMethod) WithLogging(onoff bool) error {
	return nil
}

// File upload to Azure Blob Datastore
func (ep *AzureTransportMethod) processAzureUpload(req *DronaRequest) error {
	file := req.name
	err := azure.UploadAzureBlob(ep.acName, ep.acKey, ep.container, file, req.objloc, ep.hClient)
	if err != nil {
		return err
	}
	return nil
}

// File download from Azure Blob Datastore
func (ep *AzureTransportMethod) processAzureDownload(req *DronaRequest) error {
	file := req.name
	prgChan := make(azure.NotifChan)
	defer close(prgChan)
	if req.ackback {
		go func(req *DronaRequest, prgNotif azure.NotifChan) {
			ticker := time.NewTicker(StatsUpdateTicker)
			var stats azure.UpdateStats
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
	err := azure.DownloadAzureBlob(ep.acName, ep.acKey, ep.container, file, req.objloc, ep.hClient, prgChan)
	if err != nil {
		return err
	}
	return nil
}

// File delete from Azure Blob Datastore
func (ep *AzureTransportMethod) processAzureBlobDelete(req *DronaRequest) error {
	err := azure.DeleteAzureBlob(ep.acName, ep.acKey, ep.container, req.name, ep.hClient)
	//log.Printf("Azure Blob delete status: %v", status)
	return err
}

// File list from Azure Blob Datastore
func (ep *AzureTransportMethod) processAzureBlobList(req *DronaRequest) ([]string, error, int) {
	var csize int
	var img []string
	img, err := azure.ListAzureBlob(ep.acName, ep.acKey, ep.container, ep.hClient)
	if err != nil {
		return img, err, csize
	}
	return img, nil, csize
}

func (ep *AzureTransportMethod) processAzureBlobMetaData(req *DronaRequest) (int64, string, error) {
	size, md5, err := azure.GetAzureBlobMetaData(ep.acName, ep.acKey, ep.container, req.name, ep.hClient)
	if err != nil {
		return 0, "", err
	}
	return size, md5, nil
}

func (ep *AzureTransportMethod) getContext() *DronaCtx {
	return ep.ctx
}

func (ep *AzureTransportMethod) NewRequest(opType SyncOpType, objname, objloc string, sizelimit int64, ackback bool, reply chan *DronaRequest) *DronaRequest {
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

type AzureTransportMethod struct {
	transport SyncTransportType
	aurl      string
	region    string
	container string

	//Auth
	authType string
	acName   string
	acKey    string

	failPostTime time.Time
	ctx          *DronaCtx
	hClient      *http.Client
}
