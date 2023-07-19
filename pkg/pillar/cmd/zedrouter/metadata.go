// Copyright (c) 2020-2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// A http server providing meta-data information to application instances
// at http://169.254.169.254. The source IP address is used to tell
// which app instance is sending the request

package zedrouter

import (
	"net/http"

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
	mux := http.NewServeMux()
	nh := &networkHandler{zedrouter: z}
	mux.Handle("/eve/v1/network.json", nh)
	ipHandler := &externalIPHandler{zedrouter: z}
	mux.Handle("/eve/v1/external_ipv4", ipHandler)
	hostnameHandler := &hostnameHandler{zedrouter: z}
	mux.Handle("/eve/v1/hostname", hostnameHandler)

	openstackHandler := &openstackHandler{zedrouter: z}
	mux.Handle("/openstack", openstackHandler)
	mux.Handle("/openstack/", openstackHandler)

	kubeConfigHandler := &appInstMetaHandler{
		zedrouter:       z,
		maxResponseLen:  KubeconfigFileSizeLimitInBytes,
		publishDataType: types.AppInstMetaDataTypeKubeConfig,
	}
	mux.Handle("/eve/v1/kubeconfig", kubeConfigHandler)

	AppCustomStatusHandler := &appInstMetaHandler{
		zedrouter: z,
		// For now use the same limit as Kubeconfig
		maxResponseLen:  KubeconfigFileSizeLimitInBytes,
		publishDataType: types.AppInstMetaDataCustomStatus,
	}
	mux.Handle("/eve/v1/app/appCustomStatus", AppCustomStatusHandler)

	locationInfoHandler := &locationInfoHandler{zedrouter: z}
	mux.Handle("/eve/v1/location.json", locationInfoHandler)

	wwanStatusHandler := &wwanStatusHandler{zedrouter: z}
	mux.Handle("/eve/v1/wwan/status.json", wwanStatusHandler)

	wwanMetricsHandler := &wwanMetricsHandler{zedrouter: z}
	mux.Handle("/eve/v1/wwan/metrics.json", wwanMetricsHandler)

	AppInfoHandler := &AppInfoHandler{zedrouter: z}
	mux.Handle("/eve/v1/app/info.json", AppInfoHandler)

	AppCustomBlobsHandler := &AppCustomBlobsHandler{zedrouter: z}
	mux.Handle("/eve/app-custom-blobs/", AppCustomBlobsHandler)

	zedcloudCtx := zedcloud.NewContext(z.log, zedcloud.ContextOptions{})
	signerHandler := &signerHandler{
		zedrouter:   z,
		zedcloudCtx: &zedcloudCtx,
	}
	mux.Handle("/eve/v1/tpm/signer", signerHandler)

	diagHandler := &diagHandler{zedrouter: z}
	mux.Handle("/eve/v1/diag", diagHandler)
	return mux
}
