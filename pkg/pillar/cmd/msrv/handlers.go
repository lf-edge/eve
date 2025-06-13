// Copyright (c) 2020-2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package msrv

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
)

// Struct to generate the output JSON for Network Status and Metrics
type networkStatusMetrics struct {
	IfName              string // Interface's name
	Up                  bool   // Is interface up?
	TxBytes             uint64
	RxBytes             uint64
	TxDrops             uint64
	RxDrops             uint64
	TxPkts              uint64
	RxPkts              uint64
	TxErrors            uint64
	RxErrors            uint64
	TxACLDrops          uint64 // For implicit deny/drop at end
	RxACLDrops          uint64 // For implicit deny/drop at end
	TxACLRateLimitDrops uint64 // For all rate limited rules
	RxACLRateLimitDrops uint64 // For all rate limited rules
}

func (msrv *Msrv) handleNetwork() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		msrv.Log.Tracef("networkHandler.ServeHTTP")
		remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
		externalIPs, code := msrv.getExternalIPsForApp(remoteIP)
		var ipsStr []string
		var hostname string
		for _, ip := range externalIPs {
			// Avoid returning the string <nil>
			if netutils.IsEmptyIP(ip) {
				continue
			}
			ipsStr = append(ipsStr, ip.String())
		}
		anStatus := msrv.lookupAppNetworkStatusByAppIP(remoteIP)
		if anStatus != nil {
			hostname = anStatus.UUIDandVersion.UUID.String()
		}

		enInfoObj, err := msrv.subEdgeNodeInfo.Get("global")
		if err != nil {
			errorLine := fmt.Sprintf("cannot fetch edge node information: %s", err)
			msrv.Log.Error(errorLine)
			http.Error(w, errorLine, http.StatusInternalServerError)
			return
		}
		enInfo := enInfoObj.(types.EdgeNodeInfo)
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(code)
		resp, _ := json.Marshal(map[string]interface{}{
			"caller-ip":         r.RemoteAddr,
			"external-ipv4":     strings.Join(ipsStr, ","),
			"hostname":          hostname, // Do not delete this line for backward compatibility
			"app-instance-uuid": hostname,
			"device-uuid":       enInfo.DeviceID,
			"device-name":       enInfo.DeviceName,
			"project-name":      enInfo.ProjectName,
			"project-uuid":      enInfo.ProjectID,
			"enterprise-name":   enInfo.EnterpriseName,
			"enterprise-id":     enInfo.EnterpriseID,
			// TBD: add public-ipv4 when controller tells us
		})
		w.Write(resp)
	}
}

func (msrv *Msrv) handleExternalIP() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		msrv.Log.Tracef("externalIPHandler.ServeHTTP")
		remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
		externalIPs, code := msrv.getExternalIPsForApp(remoteIP)
		w.WriteHeader(code)
		w.Header().Add("Content-Type", "text/plain")
		for _, externalIP := range externalIPs {
			// Avoid returning the string <nil>
			if !netutils.IsEmptyIP(externalIP) {
				resp := []byte(externalIP.String() + "\n")
				w.Write(resp)
			}
		}
	}
}

func (msrv *Msrv) handleHostname() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		msrv.Log.Tracef("hostnameHandler.ServeHTTP")
		remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
		anStatus := msrv.lookupAppNetworkStatusByAppIP(remoteIP)
		w.Header().Add("Content-Type", "text/plain")
		if anStatus == nil {
			w.WriteHeader(http.StatusNoContent)
			msrv.Log.Errorf("No AppNetworkStatus for %s",
				remoteIP.String())
		} else {
			w.WriteHeader(http.StatusOK)
			resp := []byte(anStatus.UUIDandVersion.UUID.String() + "\n")
			w.Write(resp)
		}
	}
}

func (msrv *Msrv) handleOpenStack() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		msrv.Log.Tracef("openstackHandler ServeHTTP request: %s", r.URL.String())
		dirname, filename := path.Split(strings.TrimSuffix(r.URL.Path, "/"))
		dirname = strings.TrimSuffix(dirname, "/")
		remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
		anStatus := msrv.lookupAppNetworkStatusByAppIP(remoteIP)
		var hostname string
		var id string
		if anStatus != nil {
			hostname = anStatus.DisplayName
			id = anStatus.UUIDandVersion.UUID.String()
		} else {
			errorLine := fmt.Sprintf("no AppNetworkStatus for %s",
				remoteIP.String())
			msrv.Log.Error(errorLine)
			http.Error(w, errorLine, http.StatusNotImplemented)
			return
		}
		anConfig := msrv.lookupAppNetworkConfig(anStatus.Key())
		if anConfig == nil {
			errorLine := fmt.Sprintf("no AppNetworkConfig for %s",
				anStatus.Key())
			msrv.Log.Error(errorLine)
			http.Error(w, errorLine, http.StatusNotImplemented)
			return
		}
		if anConfig.MetaDataType != types.MetaDataOpenStack {
			errorLine := fmt.Sprintf("no MetaDataOpenStack for %s",
				anStatus.Key())
			msrv.Log.Trace(errorLine)
			http.Error(w, errorLine, http.StatusNotFound)
			return
		}
		switch filename {
		case "openstack":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "latest")
		case "meta_data.json":
			keys := msrv.getSSHPublicKeys(anConfig)
			var keysMap []map[string]string
			publicKeys := make(map[string]string)
			for ind, key := range keys {
				keysMap = append(keysMap, map[string]string{
					"data": fmt.Sprintf("%s\n", key),
					"type": "ssh",
					"name": fmt.Sprintf("key-%d", ind),
				})
				publicKeys[fmt.Sprintf("key-%d", ind)] = fmt.Sprintf("%s\n", key)
			}
			resp, _ := json.Marshal(map[string]interface{}{
				"uuid":         id,
				"hostname":     hostname,
				"name":         hostname,
				"launch_index": 0,
				"keys":         keysMap,
				"public_keys":  publicKeys,
			})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(resp)
		case "network_data.json":
			resp, _ := json.Marshal(map[string]interface{}{
				"services": []string{},
				"networks": []string{},
			})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(resp)
		case "user_data":
			userData, err := msrv.getCloudInitUserData(anConfig)
			if err != nil {
				errorLine := fmt.Sprintf("cannot get userData for %s: %v",
					anStatus.Key(), err)
				msrv.Log.Error(errorLine)
				http.Error(w, errorLine, http.StatusInternalServerError)
				return
			}
			ud, err := base64.StdEncoding.DecodeString(userData)
			if err != nil {
				errorLine := fmt.Sprintf("cannot decode userData for %s: %v",
					anStatus.Key(), err)
				msrv.Log.Error(errorLine)
				http.Error(w, errorLine, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/yaml")
			w.WriteHeader(http.StatusOK)
			w.Write(ud)
		case "vendor_data.json":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("{}"))
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

func (msrv *Msrv) handleAppInstMeta(maxResponseLen int, publishDataType types.AppInstMetaDataType) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			msg := "appInstMetaHandler: request method is not Post"
			msrv.Log.Error(msg)
			http.Error(w, msg, http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			msg := "appInstMetaHandler: Content-Type header is not application/json"
			msrv.Log.Error(msg)
			http.Error(w, msg, http.StatusUnsupportedMediaType)
			return
		}

		kubeConfig, err := io.ReadAll(io.LimitReader(r.Body, AppInstMetadataResponseSizeLimitInBytes))
		if err != nil {
			msg := fmt.Sprintf("appInstMetaHandler: ReadAll failed: %v", err)
			msrv.Log.Error(msg)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if binary.Size(kubeConfig) > maxResponseLen {
			msg := fmt.Sprintf("appInstMetaHandler: kubeconfig size exceeds limit. Expected <= %v, actual size: %v",
				maxResponseLen, binary.Size(kubeConfig))
			msrv.Log.Error(msg)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
		anStatus := msrv.lookupAppNetworkStatusByAppIP(remoteIP)
		if anStatus == nil {
			msg := fmt.Sprintf("appInstMetaHandler: no AppNetworkStatus for %s", remoteIP.String())
			msrv.Log.Error(msg)
			http.Error(w, http.StatusText(http.StatusNoContent), http.StatusNoContent)
			return
		}

		var appInstMetaData = &types.AppInstMetaData{
			AppInstUUID: anStatus.UUIDandVersion.UUID,
			Data:        kubeConfig,
			Type:        publishDataType,
		}
		msrv.publishAppInstMetadata(appInstMetaData)
		return
	}
}

func (msrv *Msrv) handleLocationInfo() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		msrv.Log.Tracef("locationInfoHandler.ServeHTTP")
		locInfoObj, err := msrv.subLocationInfo.Get("global")
		if err != nil {
			http.Error(w, http.StatusText(http.StatusNoContent), http.StatusNoContent)
			return
		}
		locInfo := locInfoObj.(types.WwanLocationInfo)
		resp, err := json.Marshal(locInfo)
		if err != nil {
			msg := fmt.Sprintf("Failed to marshal location info: %v", err)
			msrv.Log.Error(msg)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	}
}

func (msrv *Msrv) handleWWANStatus() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		msrv.Log.Tracef("wwanStatusHandler.ServeHTTP")
		statusObj, err := msrv.subWwanStatus.Get("global")
		if err != nil {
			http.Error(w, http.StatusText(http.StatusNoContent), http.StatusNoContent)
			return
		}
		status := statusObj.(types.WwanStatus)
		// SIM card and modem (logical) names are not relevant to applications.
		// They are generated by EVE and used in the EVE<->Controller API (ZInfoDevice)
		// for reference purposes. ConfigChecksum is also cleared because it is used
		// only internally by EVE microservices.
		// All these fields will be completely omitted from the json output
		// (all have omitempty json tag).
		for i := range status.Networks {
			status.Networks[i].Module.Name = ""
			for j := range status.Networks[i].SimCards {
				status.Networks[i].SimCards[j].Name = ""
			}
		}
		resp, err := json.Marshal(status)
		if err != nil {
			msg := fmt.Sprintf("Failed to marshal WWAN status: %v", err)
			msrv.Log.Error(msg)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	}
}

func (msrv *Msrv) handleWWANMetrics() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		msrv.Log.Tracef("wwanMetricsHandler.ServeHTTP")
		metricsObj, err := msrv.subWwanMetrics.Get("global")
		if err != nil {
			http.Error(w, http.StatusText(http.StatusNoContent), http.StatusNoContent)
			return
		}
		metrics := metricsObj.(types.WwanMetrics)
		resp, err := json.Marshal(metrics)
		if err != nil {
			msg := fmt.Sprintf("Failed to marshal WWAN metrics: %v", err)
			msrv.Log.Error(msg)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	}
}

func (msrv *Msrv) handleSigner(ctrlClient *controllerconn.Client) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		msrv.Log.Tracef("signerHandler.ServeHTTP")

		if r.Method != http.MethodPost {
			msg := "signerHandler: request method is not POST"
			msrv.Log.Error(msg)
			http.Error(w, msg, http.StatusMethodNotAllowed)
			return
		}
		// One larger to make sure we detect too large below.
		payload, err := io.ReadAll(io.LimitReader(r.Body, SignerMaxSize+1))
		if err != nil {
			msg := fmt.Sprintf("signerHandler: ReadAll failed: %v", err)
			msrv.Log.Error(msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		if binary.Size(payload) > SignerMaxSize {
			msg := fmt.Sprintf("signerHandler: size exceeds limit. Expected <= %v",
				SignerMaxSize)
			msrv.Log.Error(msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
		anStatus := msrv.lookupAppNetworkStatusByAppIP(remoteIP)
		if anStatus == nil {
			msg := fmt.Sprintf("signerHandler: no AppNetworkStatus for %s",
				remoteIP.String())
			msrv.Log.Error(msg)
			http.Error(w, msg, http.StatusForbidden)
			return
		}

		resp, err := ctrlClient.AddAuthentication(bytes.NewBuffer(payload), false)
		if err != nil {
			msg := fmt.Sprintf("Failed to AddAuthentication: %v", err)
			msrv.Log.Error(msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/x-proto-binary")
		w.WriteHeader(http.StatusOK)
		w.Write(resp.Bytes())
	}
}

func (msrv *Msrv) handleDiag() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		msrv.Log.Tracef("diagHandler.ServeHTTP")

		if r.Method != http.MethodGet {
			msg := "diagHandler: request method is not GET"
			msrv.Log.Error(msg)
			http.Error(w, msg, http.StatusMethodNotAllowed)
			return
		}
		// Check that request comes from a source IP for an app instance
		// to avoid returning data to others.
		remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
		anStatus := msrv.lookupAppNetworkStatusByAppIP(remoteIP)
		if anStatus == nil {
			msg := fmt.Sprintf("diagHandler: no AppNetworkStatus for %s",
				remoteIP.String())
			msrv.Log.Error(msg)
			http.Error(w, msg, http.StatusForbidden)
			return
		}
		const diagStatefile = "/run/diag.out"

		if _, err := os.Stat(diagStatefile); err != nil && os.IsNotExist(err) {
			msg := "diagHandler: file not found"
			msrv.Log.Error(msg)
			http.Error(w, msg, http.StatusNotFound)
			return
		}
		b, err := fileutils.ReadWithMaxSize(msrv.Log, diagStatefile,
			DiagMaxSize+1)
		if err != nil {
			msg := fmt.Sprintf("diagHandler: read: %v", err)
			msrv.Log.Error(msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		if len(b) > DiagMaxSize {
			msg := fmt.Sprintf("diagHandler: size exceeds limit. Expected <= %v",
				DiagMaxSize)
			msrv.Log.Error(msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "text")
		w.WriteHeader(http.StatusOK)
		w.Write(b)
	}
}

func (msrv *Msrv) handleAppInfo() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		msrv.Log.Tracef("wwanAppInfoHandler.ServeHTTP")
		w.Header().Add("Content-Type", "application/json")

		remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
		anStatus := msrv.lookupAppNetworkStatusByAppIP(remoteIP)
		if anStatus == nil {
			msrv.Log.Errorf("Could not find network instance by ip %v", remoteIP)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("not found"))
			return
		}

		diskStatusList := msrv.lookupDiskStatusList(
			anStatus.UUIDandVersion.UUID.String())

		var appInfo types.AppInfo
		for _, st := range diskStatusList {
			if st.Devtype != "AppCustom" {
				continue
			}

			blob := types.AppBlobsAvailable{
				CustomMeta: st.CustomMeta,
				DownloadURL: fmt.Sprintf("http://%s/eve/app-custom-blobs/%s",
					MetaDataServerIP, st.DisplayName),
			}

			appInfo.AppBlobs = append(appInfo.AppBlobs, blob)
		}

		resp, _ := json.Marshal(appInfo)
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	}
}

func (msrv *Msrv) handleAppCustomBlobs() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		blobName := path.Base(r.URL.Path)

		remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
		anStatus := msrv.lookupAppNetworkStatusByAppIP(remoteIP)
		if anStatus == nil {
			msrv.Log.Errorf("Could not find network instance by ip %v", remoteIP)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("not found"))
			return
		}

		diskStatusList := msrv.lookupDiskStatusList(
			anStatus.UUIDandVersion.UUID.String())

		var blobFileLocation string
		for _, st := range diskStatusList {
			if st.Devtype != "AppCustom" {
				continue
			}

			if st.DisplayName == blobName {
				blobFileLocation = st.FileLocation
				break
			}
		}

		if blobFileLocation == "" {
			http.Error(w, r.RequestURI, http.StatusNotFound)
			return
		}

		f, err := os.Open(blobFileLocation)
		if err != nil {
			http.Error(w, r.RequestURI, http.StatusNotFound)
			return
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			http.Error(w, r.RequestURI, http.StatusNotFound)
			return
		}
		modTime := fi.ModTime()

		http.ServeContent(w, r, blobFileLocation, modTime, f)
	}
}

// handlePatchDescription returns Patch Envelopes available for app instance
func (msrv *Msrv) handlePatchDescription() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// WithPatchEnvelopesByIP middleware returns envelopes which are more than 0
		appUUID := r.Context().Value(appUUIDContextKey)
		if appUUID == nil {
			sendError(w, http.StatusInternalServerError, "Can't determine App instance")
			return
		}

		envelopes := r.Context().Value(patchEnvelopesContextKey)

		for _, pe := range envelopes.(types.PatchEnvelopeInfoList).Envelopes {
			msrv.increasePatchEnvelopeStatusCounter(appUUID.(string), pe)
		}

		b, err := patchEnvelopesJSONForAppInstance(envelopes.(types.PatchEnvelopeInfoList))
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(b)
		return
	}
}

func sendError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(code)
	w.Write([]byte(fmt.Sprintf("{\"message\": \"%s\"}", msg)))
}

// handlePatchDownload serves binary artifacts of specified patch envelope to app
// instance. Patch envelope id is specified in URL. All artifacts are compressed to
// a zip archive
func (msrv *Msrv) handlePatchDownload() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// WithPatchEnvelopesByIP middleware returns envelopes which are more than 0
		envelopes := r.Context().Value(patchEnvelopesContextKey).(types.PatchEnvelopeInfoList)
		appUUID := r.Context().Value(appUUIDContextKey).(string)

		patchID := chi.URLParam(r, "patch")
		if patchID == "" {
			sendError(w, http.StatusNoContent, "patch in route is missing")
			return
		}
		e := envelopes.FindPatchEnvelopeByID(patchID)
		if e != nil {
			path, err := os.MkdirTemp("", "patchEnvelopeZip")
			if err != nil {
				sendError(w, http.StatusInternalServerError,
					fmt.Sprintf("failed to create temp dir %v", err))
				return
			}

			// temp URL data populated in the cipher blobs for zip operation
			for _, cipher := range e.CipherBlobs {
				if cipher.EncType == types.BlobEncrytedTypeInline && cipher.Inline != nil {
					cipher.Inline.URL, err = msrv.PopulateBinaryBlobFromCipher(&cipher, true)
					if err != nil {
						sendError(w, http.StatusInternalServerError,
							fmt.Sprintf("failed to populate cipher blob %v", err))
						return
					}
				}
			}
			zipFilename, err := utils.GetZipArchive(path, *e)

			// clear the temp URL data populated in the cipher blobs
			for _, cipher := range e.CipherBlobs {
				if cipher.EncType == types.BlobEncrytedTypeInline && cipher.Inline != nil {
					cipher.Inline.URL = ""
				}
			}

			if err != nil {
				sendError(w, http.StatusInternalServerError,
					fmt.Sprintf("failed to archive binary blobs %v", err))
				return
			}

			http.ServeFile(w, r, zipFilename)
			msrv.increasePatchEnvelopeDownloadCounter(appUUID, *e)

			err = os.Remove(zipFilename)
			if err != nil {
				sendError(w, http.StatusInternalServerError,
					fmt.Sprintf("failed to delete archive %v", err))
				return
			}
			return
		}
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
}

// handlePatchFileDownload serves binary artifact of specified patch envelope to app
// instance. Patch envelope id and file name is specified in URL.
func (msrv *Msrv) handlePatchFileDownload() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// WithPatchEnvelopesByIP middleware returns envelopes which are more than 0
		envelopes := r.Context().Value(patchEnvelopesContextKey).(types.PatchEnvelopeInfoList)
		appUUID := r.Context().Value(appUUIDContextKey).(string)

		patchID := chi.URLParam(r, "patch")
		if patchID == "" {
			sendError(w, http.StatusNotFound, "patch in route is missing")
			return
		}
		fileName := chi.URLParam(r, "file")
		if fileName == "" {
			sendError(w, http.StatusNotFound, "file in route is missing")
			return
		}

		e := envelopes.FindPatchEnvelopeByID(patchID)
		if e != nil {
			if idx := types.CompletedBinaryBlobIdxByName(e.BinaryBlobs, fileName); idx != -1 {
				http.ServeFile(w, r, e.BinaryBlobs[idx].URL)
				msrv.increasePatchEnvelopeDownloadCounter(appUUID, *e)
				return
			} else if idx := types.CompletedCipherBlobIdxByName(e.CipherBlobs, fileName); idx != -1 {
				base64Data, err := msrv.PopulateBinaryBlobFromCipher(&e.CipherBlobs[idx], true)
				if err != nil {
					sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to populate cipher blob %v", err))
					return
				}
				serveBase64Data(w, r, base64Data)
				msrv.increasePatchEnvelopeDownloadCounter(appUUID, *e)
				return
			} else {
				sendError(w, http.StatusNotFound, "file is not found")
				return
			}
		}

		sendError(w, http.StatusNotFound, "patch is not found")
	}
}

// Handler to serve the base64 data
func serveBase64Data(w http.ResponseWriter, r *http.Request, base64Data string) {
	// Set the appropriate headers
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=\"data.txt\"")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(base64Data)))

	// Write the base64 data to the response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(base64Data))
}

// handleAppInstanceDiscovery returns all IP addresses of each port
// for each AppInstance if caller has allowToDiscover flag enabled
func (msrv *Msrv) handleAppInstanceDiscovery() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
		appStatus, allowToDiscover := msrv.lookupAppInstStatusByAppIP(remoteIP)
		if appStatus == nil {
			msg := fmt.Sprintf("No AppNetworkStatus for %s", remoteIP.String())
			msrv.Log.Errorf("HandleAppInstanceDiscovery: %s", msg)
			sendError(w, http.StatusNoContent, msg)
			return
		}

		if !allowToDiscover {
			msg := "This app instance is not allowed to discover"
			msrv.Log.Errorf("HandleAppInstanceDiscovery: %s", msg)
			sendError(w, http.StatusForbidden, msg)
			return
		}

		appUUID := appStatus.UUIDandVersion.UUID
		services := msrv.composeAppInstancesIPAddresses(appUUID)
		marshalled, err := json.Marshal(services)
		if err != nil {
			msg := fmt.Sprintf("Error marshalling services %v", services)
			msrv.Log.Errorf("HandleAppInstanceDiscovery: %s", msg)
			sendError(w, http.StatusInternalServerError, msg)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(marshalled)
	}
}

// handleActivateCredentialGet handles get request of the activate-credential exchange,
// it returns a json containing the EK, AIK public keys and AIK name.
func (msrv *Msrv) handleActivateCredentialGet() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		}

		ekPubByte, aikPubByte, aiKnameMarshaled, err := getActivateCredentialParams()
		if err != nil {
			msrv.Log.Errorf("handleActivateCredentialGet: %v", err)
			sendError(w, http.StatusInternalServerError, "Operation failed")
			return
		}

		activateCred := ActivateCredTpmParam{
			Ek:      base64.StdEncoding.EncodeToString(ekPubByte),
			AikPub:  base64.StdEncoding.EncodeToString(aikPubByte),
			AikName: base64.StdEncoding.EncodeToString(aiKnameMarshaled),
		}
		out, err := json.Marshal(activateCred)
		if err != nil {
			msrv.Log.Errorf("handleActivateCredentialGet: error marshaling JSON payload %v", err)
			sendError(w, http.StatusInternalServerError, "Operation failed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(out)
	}
}

// handleActivateCredentialPost handles post request of the activate-credential exchange,
// it returns a json containing the activated credential and signature of the data.
func (msrv *Msrv) handleActivateCredentialPost() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		}

		in, err := io.ReadAll(io.LimitReader(r.Body, SignerMaxSize+1))
		if err != nil {
			msrv.Log.Errorf("handleActivateCredential, ReadAll : %v", err)
			sendError(w, http.StatusInternalServerError, "Operation failed")
			return
		}

		if binary.Size(in) > SignerMaxSize {
			msrv.Log.Errorf("handleActivateCredential, size exceeds limit. Expected <= %d", SignerMaxSize)
			sendError(w, http.StatusBadRequest, "Operation failed")
			return
		}

		cred, sig, err := activateCredential(in)
		if err != nil {
			msrv.Log.Errorf("handleActivateCredential, activateCredential: %v", err)
			sendError(w, http.StatusInternalServerError, "Operation failed")
			return
		}

		activateCred := ActivateCredActivated{
			Secret: base64.StdEncoding.EncodeToString(cred),
			Sig:    base64.StdEncoding.EncodeToString(sig),
		}
		out, err := json.Marshal(activateCred)
		if err != nil {
			msrv.Log.Errorf("handleActivateCredential, error marshaling JSON payload : %v", err)
			sendError(w, http.StatusInternalServerError, "Operation failed")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(out)
	}
}

// handleNetworkStatusMetrics handles GET requests for network status and
// metrics, returning a JSON output with the information of all device used
// ports: interface name, status (up or down) and network metrics
func (msrv *Msrv) handleNetworkStatusMetrics() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		msrv.Log.Tracef("networkStatusMetricsHandler.ServeHTTP")

		// Fetch network status data
		devNetStatusObj, err := msrv.subDeviceNetworkStatus.Get("global")
		if err != nil {
			http.Error(w, http.StatusText(http.StatusNoContent), http.StatusNoContent)
			return
		}
		devNetStatus := devNetStatusObj.(types.DeviceNetworkStatus)

		// Fetch network metrics data
		metricsObj, err := msrv.subNetworkMetrics.Get("global")
		if err != nil {
			http.Error(w, http.StatusText(http.StatusNoContent), http.StatusNoContent)
			return
		}
		metrics := metricsObj.(types.NetworkMetrics)

		// List all (used) device ports
		devList := make([]networkStatusMetrics, 0)
		for _, p := range devNetStatus.Ports {
			var metric *types.NetworkMetric
			if p.IfName == "" {
				continue
			}
			for _, m := range metrics.MetricList {
				if p.IfName == m.IfName {
					metric = &m
					break
				}
			}
			if metric == nil {
				continue
			}

			ifDev := &networkStatusMetrics{
				IfName:              p.IfName,
				Up:                  p.Up,
				TxPkts:              metric.TxPkts,
				RxPkts:              metric.RxPkts,
				TxBytes:             metric.TxBytes,
				RxBytes:             metric.RxBytes,
				TxDrops:             metric.TxDrops,
				RxDrops:             metric.RxDrops,
				TxErrors:            metric.TxErrors,
				RxErrors:            metric.RxErrors,
				TxACLDrops:          metric.TxAclDrops,
				RxACLDrops:          metric.RxAclDrops,
				TxACLRateLimitDrops: metric.TxAclRateLimitDrops,
				RxACLRateLimitDrops: metric.RxAclRateLimitDrops,
			}
			devList = append(devList, *ifDev)
		}

		// Create output JSON from devList
		resp, err := json.Marshal(devList)
		if err != nil {
			msg := fmt.Sprintf("Failed to marshal network status and metrics: %v", err)
			msrv.Log.Error(msg)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	}
}

// reverseProxy is a handler which proxies request to target URL
func (msrv *Msrv) reverseProxy(target *url.URL) func(http.ResponseWriter, *http.Request) {
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(rw http.ResponseWriter, r *http.Request, err error) {
		msrv.Log.Errorf("httputil proxy error: %v", err)
		rw.WriteHeader(http.StatusBadGateway)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		r.Host = target.Host
		proxy.ServeHTTP(w, r)
	}
}
