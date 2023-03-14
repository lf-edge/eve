// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/libs/nettrace"
	"github.com/lf-edge/eve/libs/zedUpload"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/types"
	logutils "github.com/lf-edge/eve/pkg/pillar/utils/logging"
)

// Drona APIs for object Download
func handleSyncOp(ctx *downloaderContext, key string,
	config types.DownloaderConfig, status *types.DownloaderStatus,
	dst *types.DatastoreConfig, dsCtx *types.DatastoreContext,
	receiveChan chan<- CancelChannel) (bool, string) {
	var (
		err                     error
		errStr                  string
		locFilename, locDirname string
		remoteName, serverURL   string
		syncOp                  zedUpload.SyncOpType = zedUpload.SyncOpDownload
		trType                  zedUpload.SyncTransportType
		auth                    *zedUpload.AuthInput
		cancelled               bool
		contentType             string
		addrCount               int
		tracedReqs              []netdump.TracedNetRequest
	)

	// the target filename, where to place the download, is provided in config.
	// downloader has two options:
	//  * download the file part by part, filling up the `Target` until it is complete, and then sending status
	//  * create a separate cache directory elsewhere under sole downloader control, download the file part by part there,
	//    and when complete, do a single atomic copy to `Target` and send status
	// `config.Target` is where it is expected to place the final downloaded file; how it gets there
	// is up to downloader.
	// As of this writing, the file is downloaded directly to `config.Target`
	locFilename = config.Target
	locDirname = path.Dir(locFilename)
	cleanOnError := true

	// by default the metricsURL _is_ the DownloadURL, but can override in switch
	metricsURL := dsCtx.DownloadURL

	// make sure the directory exists - just a safety check
	if _, err := os.Stat(locDirname); err != nil {
		log.Tracef("Create %s", locDirname)
		if err = os.MkdirAll(locDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	downloadMaxPortCost := ctx.downloadMaxPortCost
	log.Functionf("Downloading <%s> to <%s> using %d downloadMaxPortCost",
		config.Name, locFilename, downloadMaxPortCost)

	dsPath := dsCtx.Dpath

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
			errStr = fmt.Sprintf("invalid OCI registry URL: %s", err.Error())
		}
	case zconfig.DsType_DsS3.String():
		auth = &zedUpload.AuthInput{
			AuthType: "s3",
			Uname:    dsCtx.APIKey,
			Password: dsCtx.Password,
		}
		trType = zedUpload.SyncAwsTr
		serverURL = dsCtx.DownloadURL
		// pass in the config.Name instead of 'filename' which
		// does not contain the prefix of the relative path with '/'s
		remoteName = config.Name

		// we assume that the bucket name should not contain a / and we make the remoteName pick up anything after a /
		// remove all leading '/' if we have them in dsPath, remove duplicates of '/' and split by '/'
		splittedPath := strings.Split(path.Clean(strings.TrimLeft(dsPath, "/")), "/")
		if len(splittedPath) > 1 {
			// if we have '/' in datastore path, move all after first occurrence from bucket to remoteName
			// valid bucket name should not contain '/'
			dsPath = splittedPath[0]
			splittedPath = append(splittedPath, remoteName)
			remoteName = path.Join(splittedPath[1:]...)
		}
		metricsURL = fmt.Sprintf("S3:%s/%s", dsPath, remoteName)
		cleanOnError = false

	case zconfig.DsType_DsAzureBlob.String():
		auth = &zedUpload.AuthInput{
			AuthType: "password",
			Uname:    dsCtx.APIKey,
			Password: dsCtx.Password,
		}
		trType = zedUpload.SyncAzureTr
		serverURL = strings.TrimSpace(dst.Fqdn)
		// if fqdn is defined, ensure that we have scheme defined
		// if not, assume it is https
		if serverURL != "" {
			u, err := url.Parse(serverURL)
			if err != nil {
				errStr = fmt.Sprintf("invalid fqdn(%s): %s", serverURL, err)
			} else if u.Scheme == "" {
				serverURL = fmt.Sprintf("https://%s", serverURL)
			}
		}
		// pass in the config.Name instead of 'filename' which
		// does not contain the prefix of the relative path with '/'s
		remoteName = config.Name
		cleanOnError = false

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
		serverURL = dst.Fqdn

	case zconfig.DsType_DsHttp.String(), zconfig.DsType_DsHttps.String(), "":
		auth = &zedUpload.AuthInput{
			AuthType: "http",
		}
		trType = zedUpload.SyncHttpTr
		// pass in the config.Name instead of 'filename' which
		// does not contain the prefix of the relative path with '/'s
		remoteName = config.Name
		serverURL, err = getServerURL(dsCtx)
		// failed to get server url
		if err != nil {
			errStr = errStr + "\n" + err.Error()
		}

	case zconfig.DsType_DsGoogleStorage.String():
		auth = &zedUpload.AuthInput{
			AuthType: "gs",
			Uname:    dsCtx.APIKey,
			Password: dsCtx.Password,
		}
		trType = zedUpload.SyncGSTr
		serverURL = dsCtx.DownloadURL
		// pass in the config.Name instead of 'filename' which
		// does not contain the prefix of the relative path with '/'s
		remoteName = config.Name
	default:
		errStr = "unsupported transport method " + dsCtx.TransportMethod

	}

	// if there were any errors, do not bother continuing
	// ideally in go we would have this as a check for error
	// and return, but we will get to it later
	if errStr != "" {
		log.Errorf("Error preparing to download. All errors:%s", errStr)
		return handleSyncOpResponse(ctx, config, status, locFilename,
			key, errStr, cancelled, cleanOnError)
	}

	// if the server URL ends with '.local', it is considered to be local data store
	dsLocal := strings.HasSuffix(serverURL, ".local") || strings.HasSuffix(serverURL, ".local.")
	if dsLocal {
		addrCount = 1
	} else {
		addrCount = types.CountLocalAddrNoLinkLocalWithCost(ctx.deviceNetworkStatus,
			downloadMaxPortCost)
		if addrCount == 0 {
			err := fmt.Errorf("No IP management port addresses with cost <= %d",
				downloadMaxPortCost)
			log.Error(err.Error())
			return handleSyncOpResponse(ctx, config, status, locFilename,
				key, err.Error(), cancelled, cleanOnError)
		}
	}
	// Note that network tracing of image downloads over SFTP is not supported.
	withNetTracing := ctx.netDumper != nil && !dsLocal && trType != zedUpload.SyncSftpTr
	var traceOpts []nettrace.TraceOpt
	if withNetTracing {
		// Avoid socket trace for download. Otherwise, it would increase
		// the size of the resulting netdump considerably.
		traceOpts = []nettrace.TraceOpt{
			&nettrace.WithLogging{
				CustomLogger: &base.LogrusWrapper{Log: log},
			},
			&nettrace.WithConntrack{},
			&nettrace.WithDNSQueryTrace{},
			&nettrace.WithHTTPReqTrace{
				// Do not disclose sensitive data stored inside headers,
				// record only their length.
				HeaderFields: nettrace.HdrFieldsOptValueLenOnly,
			},
		}
		if ctx.netdumpWithPCAP {
			traceOpts = append(traceOpts, &nettrace.WithPacketCapture{
				Interfaces:        types.GetMgmtPortsAny(ctx.deviceNetworkStatus, 0),
				TotalSizeLimit:    pcapSizeLimit,
				IncludeICMP:       true,
				IncludeARP:        true,
				TCPWithoutPayload: true, // Exclude TCP segments carrying downloaded data.
			})
		}
	}

	// Loop through all interfaces until a success
	for addrIndex := 0; addrIndex < addrCount; addrIndex++ {
		var ifname string
		var ipSrc net.IP
		var tracedReq netdump.TracedNetRequest
		if !dsLocal {
			ipSrc, err = types.GetLocalAddrNoLinkLocalWithCost(ctx.deviceNetworkStatus,
				addrIndex, "", downloadMaxPortCost)
			if err != nil {
				log.Errorf("GetLocalAddr failed: %s", err)
				errStr = errStr + "\n" + err.Error()
				continue
			}
			ifname = types.GetMgmtPortFromAddr(ctx.deviceNetworkStatus, ipSrc)
		} else {
			serverURL, ifname, ipSrc, err = findDSmDNS(ctx, serverURL)
			if err != nil {
				log.Errorf("find datastore mDNS failed: %s", err)
				errStr = errStr + "\n" + err.Error()
				break
			}
		}
		log.Functionf("Using server URL %s IP source %v if %s transport %v",
			serverURL, ipSrc, ifname, dsCtx.TransportMethod)

		// do the download
		st := &PublishStatus{
			ctx:    ctx,
			status: status,
		}
		downloadStartTime := time.Now()
		contentType, cancelled, tracedReq, err = download(ctx, trType, st, syncOp,
			serverURL, auth, dsPath, dsCtx.Region,
			config.Size, ifname, ipSrc, remoteName, locFilename, dst.DsCertPEM,
			withNetTracing, traceOpts, receiveChan)
		if withNetTracing {
			tracedReq.RequestName = fmt.Sprintf("download-addr%d", addrIndex)
			tracedReqs = append(tracedReqs, tracedReq)
		}
		if err != nil {
			if cancelled {
				log.Errorf("download %s cancelled", serverURL)
				errStr = "download cancelled by user"
				break
			}
			log.Errorf("Source IP %s failed: %s", ipSrc, err)
			ctx.zedcloudMetrics.RecordFailure(log, ifname, metricsURL, 1024, 0, false)
			// the error with "no suitable address found" for http schemes
			// are suppressed inside httputil library.
			// the S3 and Azure similar error have their own private error structure
			// and can only be handled with string search here.
			dnError := strings.Trim(err.Error(), "\n")
			if !strings.HasSuffix(dnError, logutils.NoSuitableAddrStr) {
				errStr = errStr + "\n" + err.Error()
			}
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
		downloadTime := int64(time.Since(downloadStartTime) / time.Millisecond)
		status.Size = uint64(size)
		status.ContentType = contentType
		ctx.zedcloudMetrics.RecordSuccess(log, ifname,
			metricsURL, 1024, size, downloadTime, false)
		if st.Progress(100, size, size) {
			log.Noticef("updated sizes at end to %d/%d",
				size, size)
		}
		if withNetTracing {
			publishNetdump(ctx, true, tracedReqs)
		}
		return handleSyncOpResponse(ctx, config, status,
			locFilename, key, "", cancelled, cleanOnError)
	}
	// we skip this error earlier but we must fill errStr
	if errStr == "" {
		errStr = logutils.NoSuitableAddrStr
	}
	if !cancelled {
		log.Errorf("All source IP addresses failed. All errors:%s",
			errStr)
	}
	if withNetTracing {
		publishNetdump(ctx, false, tracedReqs)
	}
	return handleSyncOpResponse(ctx, config, status, locFilename,
		key, errStr, cancelled, cleanOnError)
}

// DownloadURL format : http://<serverURL>/dpath/filename
func getServerURL(dsCtx *types.DatastoreContext) (string, error) {
	u, err := url.Parse(dsCtx.DownloadURL)
	if err != nil {
		log.Errorf("URL Parsing failed: %s", err)
		return "", err
	}
	return u.Scheme + "://" + u.Host, nil
}

func handleSyncOpResponse(ctx *downloaderContext, config types.DownloaderConfig,
	status *types.DownloaderStatus, locFilename,
	key, errStr string, cancelled, cleanOnError bool) (bool, string) {

	// have finished the download operation
	// based on the result, perform some storage
	// management also

	if errStr != "" {
		if cleanOnError {
			// Delete downloaded files
			doDelete(ctx, key, locFilename, status)
		}
		return cancelled, errStr
	}

	// make sure the file exists
	_, err := os.Stat(locFilename)
	if err != nil {
		// Nothing was downloaded? Delete progress files if any
		doDelete(ctx, key, locFilename, status)
		errStr := fmt.Sprintf("%v", err)
		return cancelled, errStr
	}

	err = os.RemoveAll(locFilename + progressFileSuffix)
	if err != nil {
		log.Errorf("handleSyncOpResponse(%s): failed to clean progress file %s",
			status.Name, err)
	}

	log.Functionf("handleSyncOpResponse(%s): successful <%s>",
		config.Name, locFilename)

	// Report success
	return false, ""
}

// cloud storage interface functions/APIs
func constructDatastoreContext(ctx *downloaderContext, configName string, NameIsURL bool, dst types.DatastoreConfig) (*types.DatastoreContext, error) {
	dpath := dst.Dpath
	downloadURL := configName
	if !NameIsURL {
		downloadURL = dst.Fqdn
		if len(dpath) > 0 {
			downloadURL = downloadURL + "/" + dpath
		}
		if len(configName) > 0 {
			downloadURL = downloadURL + "/" + configName
		}
	}

	// get the decrypted encryption block
	decBlock, err := getDatastoreCredential(ctx, dst)
	if err != nil {
		return nil, err
	}

	dsCtx := types.DatastoreContext{
		DownloadURL:     downloadURL,
		TransportMethod: dst.DsType,
		Dpath:           dpath,
		APIKey:          decBlock.DsAPIKey,
		Password:        decBlock.DsPassword,
		Region:          dst.Region,
	}
	return &dsCtx, nil
}

func getDatastoreCredential(ctx *downloaderContext,
	dst types.DatastoreConfig) (types.EncryptionBlock, error) {
	if dst.CipherBlockStatus.IsCipher {
		status, decBlock, err := cipher.GetCipherCredentials(&ctx.decryptCipherContext,
			dst.CipherBlockStatus)
		ctx.pubCipherBlockStatus.Publish(status.Key(), status)
		if err != nil {
			log.Errorf("%s, datastore config cipherblock decryption unsuccessful, falling back to cleartext: %v",
				dst.Key(), err)
			decBlock.DsAPIKey = dst.ApiKey
			decBlock.DsPassword = dst.Password
			// We assume IsCipher is only set when there was some
			// data. Hence this is a fallback if there is
			// some cleartext.
			if decBlock.DsAPIKey != "" || decBlock.DsPassword != "" {
				ctx.cipherMetrics.RecordFailure(log, types.CleartextFallback)
			} else {
				ctx.cipherMetrics.RecordFailure(log, types.MissingFallback)
			}
			return decBlock, nil
		}
		log.Noticef("%s, datastore config cipherblock decryption successful got %t/%t",
			dst.Key(), len(decBlock.DsAPIKey) != 0,
			len(decBlock.DsPassword) != 0)
		return decBlock, nil
	}
	log.Noticef("%s, datastore config cipherblock not present", dst.Key())
	decBlock := types.EncryptionBlock{}
	decBlock.DsAPIKey = dst.ApiKey
	decBlock.DsPassword = dst.Password
	if decBlock.DsAPIKey != "" || decBlock.DsPassword != "" {
		ctx.cipherMetrics.RecordFailure(log, types.NoCipher)
	} else {
		ctx.cipherMetrics.RecordFailure(log, types.NoData)
	}
	return decBlock, nil
}
