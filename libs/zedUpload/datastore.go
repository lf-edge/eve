// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedUpload

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/lf-edge/eve/libs/zedUpload/types"
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

//
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

//
// Interface for various transport implementation
//
type DronaEndPoint interface {
	getContext() *DronaCtx
	NewRequest(SyncOpType, string, string, int64, bool, chan *DronaRequest) *DronaRequest
	Open() error
	Action(req *DronaRequest) error
	Close() error
	WithSrcIPSelection(localAddr net.IP) error
	WithSrcIPAndHTTPSCerts(localAddr net.IP, certs [][]byte) error
	WithSrcIPAndProxySelection(localAddr net.IP, proxy *url.URL) error
	WithSrcIPAndProxyAndHTTPSCerts(localAddr net.IP, proxy *url.URL, certs [][]byte) error
	WithBindIntf(intf string) error
	WithLogging(onoff bool) error
}

// use the specific ip as source address for this connection
func httpClientSrcIP(localAddr net.IP, proxy *url.URL) *http.Client {
	// You also need to do this to make it work and not give you a
	// "mismatched local address type ip"
	// This will make the ResolveIPAddr a TCPAddr without needing to
	// say what SRC port number to use.
	localTCPAddr := net.TCPAddr{IP: localAddr}
	localUDPAddr := net.UDPAddr{IP: localAddr}
	resolverDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		switch network {
		case "udp", "udp4", "udp6":
			d := net.Dialer{LocalAddr: &localUDPAddr}
			return d.Dial(network, address)
		case "tcp", "tcp4", "tcp6":
			d := net.Dialer{LocalAddr: &localTCPAddr}
			return d.Dial(network, address)
		default:
			return nil, fmt.Errorf("unsupported address type: %v", network)
		}
	}
	r := net.Resolver{Dial: resolverDial, PreferGo: true, StrictErrors: false}
	webclient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy),
			DialContext: (&net.Dialer{
				Resolver:  &r,
				LocalAddr: &localTCPAddr,
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	return webclient
}

func httpClientAddCerts(client *http.Client, certs [][]byte) (*http.Client, error) {
	if client == nil || len(certs) == 0 {
		return client, nil
	}
	caCertPool := x509.NewCertPool()
	for _, pem := range certs {
		if !caCertPool.AppendCertsFromPEM(pem) {
			return client, fmt.Errorf("Failed to append datastore certs")
		}
	}
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: caCertPool}
	return client, nil
}

// given interface get the ip
func getSrcIpFromInterface(intf string) net.IP {
	ief, err := net.InterfaceByName(intf)
	if err == nil {
		addrs, err := ief.Addrs()
		if err == nil {
			localAddr, _, err := net.ParseCIDR(addrs[0].String())
			if err == nil {
				return localAddr
			}
		}
	}
	return nil
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
			_ = ctx.handleRequest(req)

		case <-ctx.quitChan:
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
		err = trp.Action(req)

		// No matter what post response
		ctx.postResponse(req, err)

	}()

	return err
}

func (ctx *DronaCtx) handleQuit() error {
	return nil
}

// postSize:
//  post the progress report we haven't completed the download/upload yet
func (ctx *DronaCtx) postSize(req *DronaRequest, size, asize int64) {
	req.updateOsize(size)
	req.updateAsize(asize)
	req.result <- req
}

// postChunk:
//  post the chunk data which is downloaded from the respective datastore
func (ctx *DronaCtx) postChunk(req *DronaRequest, chunkDetail ChunkData) {
	req.chunkInfoChan <- chunkDetail
	req.result <- req
}

// postResponse:
//   make sure the reply is always sent back
//
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

// NewSyncerDest:
//   - add another location end point to syncer
func (ctx *DronaCtx) NewSyncerDest(tr SyncTransportType, UrlOrRegion, PathOrBkt string, auth *AuthInput) (DronaEndPoint, error) {
	switch tr {
	case SyncAwsTr:
		syncEp := &AwsTransportMethod{transport: tr, region: UrlOrRegion, bucket: PathOrBkt, ctx: ctx}
		if auth != nil {
			syncEp.token = auth.Uname
			syncEp.apiKey = auth.Password
		}
		syncEp.failPostTime = time.Now()
		return syncEp, nil
	case SyncAzureTr:
		syncEp := &AzureTransportMethod{transport: tr, aurl: UrlOrRegion, container: PathOrBkt, ctx: ctx}
		if auth != nil {
			syncEp.authType = auth.AuthType
			syncEp.acName = auth.Uname
			syncEp.acKey = auth.Password
		}
		syncEp.failPostTime = time.Now()
		return syncEp, nil
	case SyncHttpTr:
		syncEp := &HttpTransportMethod{transport: tr, hurl: UrlOrRegion, path: PathOrBkt, ctx: ctx}
		if auth != nil {
			syncEp.authType = auth.AuthType
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
	case SyncOCIRegistryTr:
		syncEp := &OCITransportMethod{transport: tr, registry: UrlOrRegion, path: PathOrBkt, ctx: ctx}
		if auth != nil {
			syncEp.uname = auth.Uname
			syncEp.apiKey = auth.Password
		}
		syncEp.failPostTime = time.Now()
		return syncEp, nil
	case SyncGSTr:
		syncEp := &GsTransportMethod{transport: tr, bucket: PathOrBkt, ctx: ctx}
		if auth != nil {
			syncEp.projectID = auth.Uname
			syncEp.apiKey = auth.Password
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

func statsUpdater(req *DronaRequest, dronaCtx *DronaCtx, prgNotif types.StatsNotifChan) {
	ticker := time.NewTicker(StatsUpdateTicker)
	defer ticker.Stop()
	var stats types.UpdateStats
	var ok bool
	for {
		select {
		case stats, ok = <-prgNotif:
			if !ok {
				return
			}
		case <-ticker.C:
			req.doneParts = stats.DoneParts
			dronaCtx.postSize(req, stats.Size, stats.Asize)
		}
	}
}
