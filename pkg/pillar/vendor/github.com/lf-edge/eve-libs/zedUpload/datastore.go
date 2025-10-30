// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedUpload

import (
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/lf-edge/eve-libs/nettrace"
	"github.com/lf-edge/eve-libs/zedUpload/types"
	"github.com/sirupsen/logrus"
)

// Sync Operation type
type SyncOpType int

// Operation types supported
const (
	SyncOpUnknown               = 0
	SyncOpUpload                = 1
	SyncOpDownload              = 2
	SyncOpDelete                = 3
	SyncOpDownloadWithSignature = 4
	SyncOpList                  = 5
	SyncOpGetObjectMetaData     = 6
	SyncOpGetURI                = 7
	SysOpPutPart                = 8
	SysOpCompleteParts          = 9
	SysOpDownloadByChunks       = 10
	DefaultNumberOfHandlers     = 11

	StatsUpdateTicker = 1 * time.Second // timer for updating client for stats
	FailPostTimeout   = 2 * time.Minute
)

// Sync Transport Type
type SyncTransportType string

const (
	SyncAwsTr         SyncTransportType = "s3"
	SyncAzureTr       SyncTransportType = "azure"
	SyncGSTr          SyncTransportType = "google"
	SyncHttpTr        SyncTransportType = "http"
	SyncSftpTr        SyncTransportType = "sftp"
	SyncOCIRegistryTr SyncTransportType = "oci"
)

// Interface for various transport implementation
type DronaEndPoint interface {
	getContext() *DronaCtx
	NewRequest(SyncOpType, string, string, int64, bool, chan *DronaRequest) *DronaRequest
	Open() error
	Action(req *DronaRequest) error
	Close() error
	WithSrcIP(localAddr net.IP) error
	WithTrustedCerts(certs [][]byte) error
	WithProxy(proxy *url.URL) error
	WithBindIntf(intf string) error
	WithLogging(onoff bool) error
	WithNetTracing(opts ...nettrace.TraceOpt) error
	// GetNetTrace : if network tracing is enabled (WithNetTracing() was called),
	// this method returns trace of all network operations performed up to this point,
	// possibly also accompanied by per-interface packet captures (only if enabled by
	// tracing options).
	GetNetTrace(description string) (
		nettrace.AnyNetTrace, []nettrace.PacketCapture, error)
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

// Keep working till we are told otherwise
func (ctx *DronaCtx) ListenAndServe() {
	for {
		select {
		case req, ok := <-ctx.reqChan:
			if ok {
				logrus.Infof("ListenAndServe got request")
				_ = ctx.handleRequest(req)
			} else {
				logrus.Infof("ListenAndServe reqChan closed")
				return
			}
		case <-ctx.quitChan:
			logrus.Infof("ListenAndServe quitChan")
			_ = ctx.handleQuit()
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
		err := trp.Action(req)

		// No matter what post response
		ctx.postResponse(req, err)

	}()

	return err
}

func (ctx *DronaCtx) handleQuit() error {
	return nil
}

// postSize:
//
//	post the progress report we haven't completed the download/upload yet
func (ctx *DronaCtx) postSize(req *DronaRequest, size, asize int64) {
	req.updateOsize(size)
	req.updateAsize(asize)
	req.result <- req
}

// postChunk:
//
//	post the chunk data which is downloaded from the respective datastore
func (ctx *DronaCtx) postChunk(req *DronaRequest, chunkDetail ChunkData) {
	req.chunkInfoChan <- chunkDetail
	req.result <- req
}

// postResponse:
//
//	make sure the reply is always sent back
func (ctx *DronaCtx) postResponse(req *DronaRequest, status error) {
	// status is already set up by action, we just have to set processed flag
	req.setProcessed()
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

// SyncerDestOption is a function that configures a DronaEndpoint.
// It is expected to check that the passed DronaEndpoint is of the correct type for it and, if not,
// return an error.
type SyncerDestOption func(endpoint DronaEndPoint) error

// NewSyncerDest add another location end point to syncer.
// The options are passed directly to the specific transport and should match its type.
func (ctx *DronaCtx) NewSyncerDest(tr SyncTransportType, UrlOrRegion, nettraceDirPATH, PathOrBkt string, auth *AuthInput, opts ...SyncerDestOption) (DronaEndPoint, error) {
	var endpoint DronaEndPoint
	switch tr {
	case SyncAwsTr:
		syncEp := &AwsTransportMethod{transport: tr, region: UrlOrRegion, bucket: PathOrBkt, ctx: ctx}
		if auth != nil {
			syncEp.token = auth.Uname
			syncEp.apiKey = auth.Password
		}
		syncEp.hClientWrap = &httpClientWrapper{}
		syncEp.hClientWrap.nettraceDirPath = nettraceDirPATH
		syncEp.failPostTime = time.Now()
		endpoint = syncEp
	case SyncAzureTr:
		syncEp := &AzureTransportMethod{transport: tr, aurl: UrlOrRegion, container: PathOrBkt, ctx: ctx}
		if auth != nil {
			syncEp.authType = auth.AuthType
			syncEp.acName = auth.Uname
			syncEp.acKey = auth.Password
		}
		syncEp.hClientWrap = &httpClientWrapper{}
		syncEp.hClientWrap.nettraceDirPath = nettraceDirPATH
		syncEp.failPostTime = time.Now()
		endpoint = syncEp
	case SyncHttpTr:
		syncEp := &HttpTransportMethod{transport: tr, hurl: UrlOrRegion, path: PathOrBkt, ctx: ctx}
		if auth != nil {
			syncEp.authType = auth.AuthType
		}
		syncEp.hClientWrap = &httpClientWrapper{}
		syncEp.hClientWrap.nettraceDirPath = nettraceDirPATH
		syncEp.failPostTime = time.Now()
		endpoint = syncEp
	case SyncSftpTr:
		syncEp := &SftpTransportMethod{transport: tr, surl: UrlOrRegion, path: PathOrBkt, ctx: ctx}
		if auth != nil {
			syncEp.authType = auth.AuthType
			syncEp.uname = auth.Uname
			syncEp.passwd = auth.Password
			syncEp.keys = auth.Keys
		}
		syncEp.failPostTime = time.Now()
		endpoint = syncEp
	case SyncOCIRegistryTr:
		syncEp := &OCITransportMethod{transport: tr, registry: UrlOrRegion, path: PathOrBkt, ctx: ctx}
		if auth != nil {
			syncEp.uname = auth.Uname
			syncEp.apiKey = auth.Password
		}
		syncEp.hClientWrap = &httpClientWrapper{}
		syncEp.hClientWrap.nettraceDirPath = nettraceDirPATH
		syncEp.failPostTime = time.Now()
		endpoint = syncEp
	case SyncGSTr:
		syncEp := &GsTransportMethod{transport: tr, bucket: PathOrBkt, ctx: ctx}
		if auth != nil {
			syncEp.projectID = auth.Uname
			syncEp.apiKey = auth.Password
		}
		syncEp.hClientWrap = &httpClientWrapper{}
		syncEp.hClientWrap.nettraceDirPath = nettraceDirPATH
		syncEp.failPostTime = time.Now()
		endpoint = syncEp
	default:
		return nil, fmt.Errorf("unknown transport type %v", tr)
	}

	for _, opt := range opts {
		if err := opt(endpoint); err != nil {
			return nil, err
		}
	}
	return endpoint, nil
}

// NewDronaCtx
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

func reqPostSize(req *DronaRequest, dronaCtx *DronaCtx, stats types.UpdateStats) {
	req.Lock()
	req.doneParts = stats.DoneParts
	req.Unlock()
	dronaCtx.postSize(req, stats.Size, stats.Asize)
}

func statsUpdater(req *DronaRequest, dronaCtx *DronaCtx, prgNotif types.StatsNotifChan) {
	ticker := time.NewTicker(StatsUpdateTicker)
	defer ticker.Stop()
	var newStats, stats types.UpdateStats
	var ok bool
	for {
		select {
		case newStats, ok = <-prgNotif:
			if !ok {
				reqPostSize(req, dronaCtx, stats)
				return
			}
			stats = newStats
		case <-ticker.C:
			reqPostSize(req, dronaCtx, stats)
		}
	}
}
