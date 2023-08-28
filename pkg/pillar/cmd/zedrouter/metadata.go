// Copyright (c) 2020-2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// A http server providing meta-data information to application instances
// at http://169.254.169.254. The source IP address is used to tell
// which app instance is sending the request

package zedrouter

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
)

// KubeconfigFileSizeLimitInBytes holds the maximum expected size of Kubeconfig file
// received from k3s server appInst.
// Note: KubeconfigFileSizeLimitInBytes should always be < AppInstMetadataResponseSizeLimitInBytes.
const KubeconfigFileSizeLimitInBytes = 32768 // 32KB

// AppInstMetadataResponseSizeLimitInBytes holds the maximum expected size of appInst
// metadata received in the response.
// Note: KubeconfigFileSizeLimitInBytes should always be < AppInstMetadataResponseSizeLimitInBytes.
const AppInstMetadataResponseSizeLimitInBytes = 35840 // 35KB

// SignerMaxSize is how large objects we will sign
const SignerMaxSize = 65535

// DiagMaxSize is the max returned size for diag
const DiagMaxSize = 65535

func (z *zedrouter) makeMetadataHandler() http.Handler {
	r := chi.NewRouter()

	nh := &networkHandler{zedrouter: z}
	r.Get("/eve/v1/network.json", nh.ServeHTTP)

	ipHandler := &externalIPHandler{zedrouter: z}
	r.Get("/eve/v1/external_ipv4", ipHandler.ServeHTTP)

	hostnameHandler := &hostnameHandler{zedrouter: z}
	r.Get("/eve/v1/hostname", hostnameHandler.ServeHTTP)

	openstackHandler := &openstackHandler{zedrouter: z}
	r.Get("/openstack", openstackHandler.ServeHTTP)
	r.Get("/openstack/", openstackHandler.ServeHTTP)

	kubeConfigHandler := &appInstMetaHandler{
		zedrouter:       z,
		maxResponseLen:  KubeconfigFileSizeLimitInBytes,
		publishDataType: types.AppInstMetaDataTypeKubeConfig,
	}
	r.Get("/eve/v1/kubeconfig", kubeConfigHandler.ServeHTTP)

	AppCustomStatusHandler := &appInstMetaHandler{
		zedrouter: z,
		// For now use the same limit as Kubeconfig
		maxResponseLen:  KubeconfigFileSizeLimitInBytes,
		publishDataType: types.AppInstMetaDataCustomStatus,
	}
	r.Get("/eve/v1/app/appCustomStatus", AppCustomStatusHandler.ServeHTTP)

	locationInfoHandler := &locationInfoHandler{zedrouter: z}
	r.Get("/eve/v1/location.json", locationInfoHandler.ServeHTTP)

	wwanStatusHandler := &wwanStatusHandler{zedrouter: z}
	r.Get("/eve/v1/wwan/status.json", wwanStatusHandler.ServeHTTP)

	wwanMetricsHandler := &wwanMetricsHandler{zedrouter: z}
	r.Get("/eve/v1/wwan/metrics.json", wwanMetricsHandler.ServeHTTP)

	AppInfoHandler := &AppInfoHandler{zedrouter: z}
	r.Get("/eve/v1/app/info.json", AppInfoHandler.ServeHTTP)

	AppCustomBlobsHandler := &AppCustomBlobsHandler{zedrouter: z}
	r.Get("/eve/app-custom-blobs/", AppCustomBlobsHandler.ServeHTTP)

	zedcloudCtx := zedcloud.NewContext(z.log, zedcloud.ContextOptions{})
	signerHandler := &signerHandler{
		zedrouter:   z,
		zedcloudCtx: &zedcloudCtx,
	}
	r.Get("/eve/v1/tpm/signer", signerHandler.ServeHTTP)

	diagHandler := &diagHandler{zedrouter: z}
	r.Get("/eve/v1/diag", diagHandler.ServeHTTP)

	r.Get("/eve/v1/patch/description", HandlePatchDescription(z))

	return r
}
