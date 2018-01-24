package zedUpload

import (
	"fmt"
	"github.com/zededa/shared/libs/zedUpload/awsutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

//
//
func (ep *AwsTransportMethod) Action(req *DronaRequest) error {
	var err error
	var size int

	switch req.operation {
	case SyncOpUpload:
		err, size = ep.processS3Upload(req)
	case SyncOpDownload:
		err, size = ep.processS3Download(req)
	case SyncOpDelete:
		err = ep.processS3Delete(req)
	}

	req.asize = int64(size)
	if err != nil {
		req.status = fmt.Sprintf("%v", err)
	}

	return err
}

func (ep *AwsTransportMethod) Open() error {
	return nil
}

func (ep *AwsTransportMethod) Close() error {
	return nil
}

// use the specific ip as source address for this connection
func (ep *AwsTransportMethod) WithSrcIpSelection(localAddr net.IP) error {
	ep.hClient = httpClientSrcIP(localAddr)
	return nil
}

// bind to specific interface for this connection
func (ep *AwsTransportMethod) WithBindIntf(intf string) error {
	localAddr := getSrcIpFromInterface(intf)
	if localAddr != nil {
		ep.hClient = httpClientSrcIP(localAddr)
		return nil
	}
	return fmt.Errorf("failed to get the address for intf")
}

func (ep *AwsTransportMethod) WithLogging(onoff bool) error {
	return nil
}

//
// s3uploader
func (ep *AwsTransportMethod) processS3Upload(req *DronaRequest) (error, int) {
	fInfo, err := os.Stat(req.objloc)
	if err != nil {
		return err, 0
	}
	// FiXME: strings.TrimSuffix needs to go away once final soultion is done.
	// upload, always the compression file.
	location, err := aws.S3UploadFile(ep.hClient, ep.region, ep.token, ep.apiKey,
		ep.bucket, req.name, req.objloc, false)
	if len(location) > 0 {
		req.objloc = location
	}
	return err, int(fInfo.Size())
}

//
// s3downloader
func (ep *AwsTransportMethod) processS3Download(req *DronaRequest) (error, int) {
	var csize int
	pwd := strings.TrimSuffix(ep.apiKey, "\n")
	if req.ackback {
		s := aws.NewAwsCtx(ep.token, pwd, ep.region, ep.hClient)
		if s != nil {
			err, length := s.GetObjectSize(ep.bucket, req.name)
			if err == nil {
				ep.ctx.postSize(req, length, 0)
			}
		}
	}

	err := aws.S3DownloadFile(ep.hClient, ep.region, ep.token, pwd, ep.bucket, req.name, req.objloc)
	if err == nil {
		// check for download complete
		st, err := os.Stat(req.objloc)
		if err != nil {
			return err, 0
		}
		csize = int(st.Size())
	}

	return err, csize
}

// s3delete
func (ep *AwsTransportMethod) processS3Delete(req *DronaRequest) error {
	var err error
	s3ctx := aws.NewAwsCtx(ep.token, ep.apiKey, ep.region, ep.hClient)
	if s3ctx != nil {
		err = s3ctx.DeleteObject(ep.bucket, req.name)
	} else {
		return fmt.Errorf("no s3 context")
	}
	if err != nil {
		return err
	}
	log.Printf("Successfully deleted file from %s, bucket:%s, %s", ep.token, ep.bucket, req.name)

	return err
}

func (ep *AwsTransportMethod) NewRequest(opType SyncOpType, objname, objloc string, sizelimit int64, ackback bool, reply chan *DronaRequest) *DronaRequest {
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

func (ep *AwsTransportMethod) getContext() *DronaCtx {
	return ep.ctx
}

type AwsTransportMethod struct {
	transport SyncTransportType
	bucket    string
	region    string

	//Auth
	token  string
	apiKey string

	failPostTime time.Time
	ctx          *DronaCtx
	hClient      *http.Client
}
