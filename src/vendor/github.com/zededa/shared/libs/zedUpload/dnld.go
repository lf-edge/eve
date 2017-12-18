package zedUpload

import (
	"sync"
	"time"
	"fmt"
)

//
// Sync Operation type
type SyncOpType int

// Operation types supported
const (
        SyncOpUnknown               = 0
        SyncOpUpload                = 1
        SyncOpDownload              = 2
        SyncOpDelete                = 3
        SyncOpDownloadWithSignature = 4

	DefaultNumberOfHandlers     = 10
)

//
// Sync Transport Type
type SyncTransportType string
const (
	SyncHttpTr SyncTransportType = "http"
	SyncAwsTr SyncTransportType = "s3"
	SyncSftpTr SyncTransportType = "sftp"
)

//
// Interface for various transport implementation
//
type DronaEndPoint interface {
	getContext() *DronaCtx
	NewRequest(SyncOpType, string, string, int64, bool, chan *DronaRequest) *DronaRequest
	Open() error
	Action(req *DronaRequest) error
	Close() error
}

type DronaCtx struct {
        reqChan  chan *DronaRequest
        respChan chan *DronaRequest

        // Number of handlers
        noHandlers int

	// add waitGroups here
	wg *sync.WaitGroup

        // Also open the quit channel so that we can bail
        quitChan chan bool
}

//Keep working till we are told otherwise
func (ctx *DronaCtx) ListenAndServe() {
        for {
                select {
                case req := <-ctx.reqChan:
                        ctx.handleRequest(req)

                case <-ctx.quitChan:
                        ctx.handleQuit()
                        return
                }
        }
}

func (ctx *DronaCtx) handleRequest(req *DronaRequest) error {
        var err error

	trp := req.syncEp
	if trp == nil {
		err = fmt.Errorf("No transport")
		return err	
	}
        go func() {
		err = trp.Action(req)

                // No matter what post response
                ctx.postResponse(req, err)

        }()

        return err
}

func (ctx *DronaCtx) handleQuit() error {
	return nil
}

// Do a wget to get the object
func (ctx *DronaCtx) postSize(req *DronaRequest, size, asize int64) {
//        req.setInprogress()
//        req.UpdateSize(size)
//       req.updateAsize(asize)
        req.result <- req
}

// postResponse:
//   make sure the reply is always sent back
//
func (ctx *DronaCtx) postResponse(req *DronaRequest, status error) {
        req.result <- req
}

type AuthInput struct {
	// type of auth
	AuthType string

	// required, auth for whom
	Uname string

	// optional, password
	Password string

	// optional, keytabs
	Keys []string
}

// NewSyncerDest:
//   - add another location end point to syncer
func (ctx *DronaCtx) NewSyncerDest(tr SyncTransportType, UrlOrRegion, PathOrBkt string, auth *AuthInput) (DronaEndPoint, error) {
	switch tr {
	case SyncHttpTr:
	case SyncAwsTr:
		syncEp := &AwsTransportMethod{transport: tr, region: UrlOrRegion, bucket: PathOrBkt, ctx: ctx}
		if auth != nil {
			syncEp.token = auth.Uname
			syncEp.apiKey = auth.Password
		}
		syncEp.failPostTime = time.Now()
		return syncEp, nil
	case SyncSftpTr:
		syncEp := &SftpTransportMethod{transport: tr, surl: UrlOrRegion, path: PathOrBkt, ctx: ctx}
		if auth != nil {
			syncEp.authType = auth.AuthType
			syncEp.uname = auth.Uname
			syncEp.passwd = auth.Password
			syncEp.keys = auth.Keys
		}
		syncEp.failPostTime = time.Now()
		return syncEp, nil
	default:
	}

	return nil, fmt.Errorf("unknown transport type %v", tr)
}

// NewDronaCtx
//
func NewDronaCtx(name string, noHandlers int) (*DronaCtx, error) {
        dSync := DronaCtx{}

        // Setup the load value
        dSync.noHandlers = noHandlers
        if noHandlers == 0 {
                dSync.noHandlers = DefaultNumberOfHandlers
        }

	wg := new(sync.WaitGroup)
	dSync.wg = wg

        // Finally make channels
        dSync.reqChan = make(chan *DronaRequest, dSync.noHandlers)
        dSync.respChan = make(chan *DronaRequest, dSync.noHandlers)
        dSync.quitChan = make(chan bool)

        // Initialize syncer handlers and start listening
        for i := 0; i < dSync.noHandlers; i++ {
	        wg.Add(1)
                go func() {
			defer wg.Done()
                        dSync.ListenAndServe()
                }()
        }

        return &dSync, nil
}
