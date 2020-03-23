// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedUpload

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
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

	switch req.operation {
	case SyncOpDownload:
		size, err = ep.processDownload(req)
	case SyncOpUpload:
		size, err = ep.processUpload(req)
	case SyncOpDelete:
		err = ep.processDelete(req)
	case SyncOpList:
		list, err = ep.processList(req)
		req.imgList = list
	case SyncOpGetObjectMetaData:
		contentLength, err = ep.processObjectMetaData(req)
		req.contentLength = contentLength
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
func (ep *OCITransportMethod) processDownload(req *DronaRequest) (int64, error) {
	var (
		err           error
		size          int64
		imageManifest []byte
	)
	if ep.registry == "" {
		return size, fmt.Errorf("cannot download from blank registry")
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

	// Pull down the image in the standard tar format
	_, imageManifest, size, err = ociutil.Pull(ep.registry, ep.path, req.objloc, ep.uname, ep.apiKey, ep.hClient, prgChan)
	if err != nil {
		return size, err
	}

	// add the imageManifest to the tar file
	err = appendImageManifest(req.objloc, imageManifest)
	if err != nil {
		return size, fmt.Errorf("unable to append image manifest to tar at %s: %v", req.objloc, err)
	}
	err = appendImageRepositories(req.objloc, ep.registry, ep.path, imageManifest)

	// zedUpload's job is to download an OCI image as a v1 tar file. Done.
	return size, nil
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
func (ep *OCITransportMethod) processObjectMetaData(req *DronaRequest) (int64, error) {
	var (
		err  error
		size int64
	)
	if ep.registry == "" {
		return size, fmt.Errorf("cannot download from blank registry")
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
	_, _, size, err = ociutil.Manifest(ep.registry, ep.path, ep.uname, ep.apiKey, ep.hClient, prgChan)
	if err != nil {
		return 0, err
	}
	return size, nil
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

// appendToTarfile add the given bytes to the tarfile with the given filename
func appendToTarfile(tarfile, filename string, content []byte) error {
	var (
		f   *os.File
		err error
	)
	// open the existing file
	if f, err = os.OpenFile(tarfile, os.O_RDWR, os.ModePerm); err != nil {
		return err
	}
	defer f.Close()
	// there always is padding at the end of a tar archive, so skip to the end
	// of the actual archive, so it will be read
	if _, err = f.Seek(-2<<9, os.SEEK_END); err != nil {
		return err
	}

	tw := tar.NewWriter(f)

	hdr := &tar.Header{
		Name: filename,
		Size: int64(len(content)),
	}

	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("failed to write %s tar header: %v", filename, err)
	}

	if _, err := tw.Write(content); err != nil {
		return fmt.Errorf("failed to write %s tar body: %v", filename, err)
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("failed to close tar writer: %v", err)
	}
	return nil
}

// appendImageManifest add the given manifest to the given tar file. Opinionated
// about the name of the file to "imagemanifest-<hash>.json"
func appendImageManifest(tarfile string, manifest []byte) error {
	hash := sha256.Sum256(manifest)
	return appendToTarfile(tarfile, fmt.Sprintf("%s-%x.json", "imagemanifest", hash), manifest)
}

func appendImageRepositories(tarfile, registry, path string, imageManifest []byte) error {
	// get the top layer for the manifest bytes
	layerHash, err := ociutil.DockerHashFromManifest(imageManifest)
	if err != nil {
		return fmt.Errorf("unable to get top layer hash: %v", err)
	}
	// need to take out the tag
	parts := strings.Split(path, ":")
	var tag, repo string
	switch len(parts) {
	case 0:
		return fmt.Errorf("malformed repository path %s", path)
	case 1:
		repo = parts[0]
		tag = "latest"
	case 2:
		repo = parts[0]
		tag = parts[1]
	default:
		return fmt.Errorf("malformed repository path has too many ':' %s", path)
	}
	fullRepo := fmt.Sprintf("%s/%s", registry, repo)
	// now build the tag we are after
	var data = map[string]map[string]string{}
	data[fullRepo] = map[string]string{}
	data[fullRepo][tag] = layerHash

	j, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("unable to convert repositories data to json: %v", err)
	}

	return appendToTarfile(tarfile, "repositories", j)
}
