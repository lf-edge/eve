package downloader

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedUpload"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	log "github.com/sirupsen/logrus"
)

// Drona APIs for object Download
func handleSyncOp(ctx *downloaderContext, key string,
	config types.DownloaderConfig, status *types.DownloaderStatus,
	dst *types.DatastoreConfig) {
	var (
		err                                        error
		errStr, locFilename, remoteName, serverURL string
		syncOp                                     zedUpload.SyncOpType = zedUpload.SyncOpDownload
		trType                                     zedUpload.SyncTransportType
		auth                                       *zedUpload.AuthInput
	)

	if status.ObjType == "" {
		log.Fatalf("handleSyncOp: No ObjType for %s\n",
			status.ImageID)
	}

	// get the datastore context
	dsCtx := constructDatastoreContext(config, status, dst)

	// by default the metricsURL _is_ the DownloadURL, but can override in switch
	metricsUrl := dsCtx.DownloadURL

	locDirname := types.DownloadDirname + "/" + status.ObjType
	locFilename = locDirname + "/pending"
	// XXX common routines to determine pathnames?
	locFilename = locFilename + "/" + config.ImageID.String()

	// update status to DOWNLOAD STARTED
	status.FileLocation = locFilename
	status.State = types.DOWNLOAD_STARTED
	publishDownloaderStatus(ctx, status)

	if _, err := os.Stat(locFilename); err != nil {
		log.Debugf("Create %s\n", locFilename)
		if err = os.MkdirAll(locFilename, 0755); err != nil {
			log.Fatal(err)
		}
	}

	filename := config.Name // XXX set for containers?
	locFilename = locFilename + "/" + config.Name

	log.Infof("Downloading <%s> to <%s> using %v allow non-free port\n",
		config.Name, locFilename, config.AllowNonFreePort)

	var addrCount int
	if !config.AllowNonFreePort {
		addrCount = types.CountLocalAddrFreeNoLinkLocal(ctx.deviceNetworkStatus)
		log.Infof("Have %d free management port addresses\n", addrCount)
		err = errors.New("No free IP management port addresses for download")
	} else {
		addrCount = types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus)
		log.Infof("Have %d any management port addresses\n", addrCount)
		err = errors.New("No IP management port addresses for download")
	}
	if addrCount == 0 {
		errStr = err.Error()
	}

	switch dsCtx.TransportMethod {
	case zconfig.DsType_DsContainerRegistry.String():
		auth = &zedUpload.AuthInput{
			AuthType: "apikey",
			Uname:    dsCtx.APIKey,
			Password: dsCtx.Password,
		}
		trType = zedUpload.SyncOCIRegistryTr
		// get the name of the repository and the URL for the registry
		serverURL, remoteName, err = ociRepositorySplit(dsCtx.DownloadURL)
		if err != nil {
			errStr = fmt.Sprintf("invalid OCI registry URL: %s", serverURL)
		}
	case zconfig.DsType_DsS3.String():
		auth = &zedUpload.AuthInput{
			AuthType: "s3",
			Uname:    dsCtx.APIKey,
			Password: dsCtx.Password,
		}
		trType = zedUpload.SyncAwsTr
		serverURL = dsCtx.DownloadURL
		remoteName = filename
		metricsUrl = fmt.Sprintf("S3:%s/%s", dsCtx.Dpath, filename)

	case zconfig.DsType_DsAzureBlob.String():
		auth = &zedUpload.AuthInput{
			AuthType: "password",
			Uname:    dsCtx.APIKey,
			Password: dsCtx.Password,
		}
		trType = zedUpload.SyncAzureTr
		serverURL = dsCtx.DownloadURL
		// pass in the config.Name instead of 'filename' which
		// does not contain the prefix of the relative path with '/'s
		remoteName = config.Name

	case zconfig.DsType_DsSFTP.String():
		auth = &zedUpload.AuthInput{
			AuthType: "sftp",
			Uname:    dsCtx.APIKey,
			Password: dsCtx.Password,
		}
		trType = zedUpload.SyncSftpTr
		// pass in the config.Name instead of 'filename' which
		// does not contain the prefix of the relative path with '/'s
		remoteName = config.Name
		serverURL, err = getServerUrl(dsCtx)
		// failed to get server url
		if err != nil {
			errStr = errStr + "\n" + err.Error()
		}

	case zconfig.DsType_DsHttp.String(), zconfig.DsType_DsHttps.String(), "":
		auth = &zedUpload.AuthInput{
			AuthType: "http",
		}
		trType = zedUpload.SyncHttpTr
		// pass in the config.Name instead of 'filename' which
		// does not contain the prefix of the relative path with '/'s
		remoteName = config.Name
		serverURL, err = getServerUrl(dsCtx)
		// failed to get server url
		if err != nil {
			errStr = errStr + "\n" + err.Error()
		}

	default:
		errStr = "unsupported transport method " + dsCtx.TransportMethod

	}

	// if there were any errors, do not bother continuing
	// ideally in go we would have this as a check for error
	// and return, but we will get to it later
	if errStr != "" {
		log.Errorf("Error preparing to download. All errors:%s\n", errStr)
		handleSyncOpResponse(ctx, config, status, locFilename,
			key, errStr)
		return
	}

	// Loop through all interfaces until a success
	for addrIndex := 0; addrIndex < addrCount; addrIndex += 1 {
		var ipSrc net.IP
		if !config.AllowNonFreePort {
			ipSrc, err = types.GetLocalAddrFreeNoLinkLocal(ctx.deviceNetworkStatus,
				addrIndex, "")
		} else {
			// Note that GetLocalAddrAny has the free ones first
			ipSrc, err = types.GetLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus,
				addrIndex, "")
		}
		if err != nil {
			log.Errorf("GetLocalAddr failed: %s\n", err)
			errStr = errStr + "\n" + err.Error()
			continue
		}
		ifname := types.GetMgmtPortFromAddr(ctx.deviceNetworkStatus, ipSrc)
		log.Infof("Using IP source %v if %s transport %v\n",
			ipSrc, ifname, dsCtx.TransportMethod)

		// do the download
		st := &PublishStatus{
			ctx:    ctx,
			status: status,
		}
		err = download(ctx, trType, st, syncOp, serverURL, auth,
			dsCtx.Dpath, dsCtx.Region,
			config.Size, ifname, ipSrc, remoteName, locFilename)
		if err != nil {
			sourceFailureError(ipSrc.String(), ifname, metricsUrl, err)
			errStr = errStr + "\n" + err.Error()
			continue
		}
		// Record how much we downloaded
		size := int64(0)
		info, err := os.Stat(locFilename)
		if err != nil {
			log.Error(err)
		} else {
			size = info.Size()
		}
		zedcloud.ZedCloudSuccess(ifname,
			metricsUrl, 1024, size)
		handleSyncOpResponse(ctx, config, status,
			locFilename, key, "")
		return

	}
	log.Errorf("All source IP addresses failed. All errors:%s\n", errStr)
	handleSyncOpResponse(ctx, config, status, locFilename,
		key, errStr)
}

// DownloadURL format : http://<serverURL>/dpath/filename
func getServerUrl(dsCtx *types.DatastoreContext) (string, error) {
	u, err := url.Parse(dsCtx.DownloadURL)
	if err != nil {
		log.Errorf("URL Parsing failed: %s\n", err)
		return "", err
	}
	return u.Scheme + "://" + u.Host, nil
}

func handleSyncOpResponse(ctx *downloaderContext, config types.DownloaderConfig,
	status *types.DownloaderStatus, locFilename string,
	key string, errStr string) {

	if status.ObjType == "" {
		log.Fatalf("handleSyncOpResponse: No ObjType for %s\n",
			status.ImageID)
	}
	locDirname := types.DownloadDirname + "/" + status.ObjType
	if errStr != "" {
		// Delete file
		doDelete(ctx, key, locDirname, status)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = errStr
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		publishDownloaderStatus(ctx, status)
		log.Errorf("handleSyncOpResponse failed for %s, <%s>\n",
			status.Name, errStr)
		return
	}

	info, err := os.Stat(locFilename)
	if err != nil {
		log.Errorf("handleSyncOpResponse Stat failed for %s <%s>\n",
			status.Name, err)
		// Delete file
		doDelete(ctx, key, locDirname, status)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		publishDownloaderStatus(ctx, status)
		return
	}
	status.Size = uint64(info.Size())

	// Update globalStatus and status
	unreserveSpace(ctx, status)

	log.Infof("handleSyncOpResponse successful <%s> <%s>\n",
		config.Name, locFilename)
	// We do not clear any status.RetryCount, LastErr, etc. The caller
	// should look at State == DOWNLOADED to determine it is done.

	status.ModTime = time.Now()
	status.PendingAdd = false
	status.State = types.DOWNLOADED
	status.Progress = 100 // Just in case
	publishDownloaderStatus(ctx, status)
}

// cloud storage interface functions/APIs
func constructDatastoreContext(config types.DownloaderConfig, status *types.DownloaderStatus, dst *types.DatastoreConfig) *types.DatastoreContext {
	dpath := dst.Dpath
	if status.ObjType == types.CertObj {
		dpath = strings.Replace(dpath, "-images", "-certs", 1)
	}
	downloadURL := config.Name
	if !config.NameIsURL {
		downloadURL = dst.Fqdn
		if len(dpath) > 0 {
			downloadURL = downloadURL + "/" + dpath
		}
		if len(config.Name) > 0 {
			downloadURL = downloadURL + "/" + config.Name
		}
	}
	dsCtx := types.DatastoreContext{
		DownloadURL:     downloadURL,
		TransportMethod: dst.DsType,
		Dpath:           dpath,
		APIKey:          dst.ApiKey,
		Password:        dst.Password,
		Region:          dst.Region,
	}
	return &dsCtx
}

func sourceFailureError(ip, ifname, url string, err error) {
	log.Errorf("Source IP %s failed: %s\n", ip, err)
	zedcloud.ZedCloudFailure(ifname, url, 1024, 0)
}
