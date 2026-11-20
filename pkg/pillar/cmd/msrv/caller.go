// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package msrv

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// Caller kinds.
const (
	CallerKindAppInstance = "eve-app-instance"
	CallerKindPod         = "k8s-pod"
)

// CallerIdentity names the workload behind a request's source address. It is
// what a TPM quote binds, so the fields must identify the workload to a
// verifier holding the deployment's enrollment record.
type CallerIdentity struct {
	Kind string `json:"kind"`

	// EVE app instance.
	AppUUID    string `json:"app_uuid,omitempty"`
	AppVersion string `json:"app_version,omitempty"`
	AppName    string `json:"app_name,omitempty"`

	// Kubernetes pod (EVE-k).
	Namespace      string              `json:"namespace,omitempty"`
	PodName        string              `json:"pod_name,omitempty"`
	PodUID         string              `json:"pod_uid,omitempty"`
	ServiceAccount string              `json:"service_account,omitempty"`
	NodeName       string              `json:"node_name,omitempty"`
	Containers     []ContainerIdentity `json:"containers,omitempty"`
}

// ContainerIdentity is one container of a pod as kubelet reports it.
type ContainerIdentity struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	// ImageID is the resolved image reference, normally with its digest.
	ImageID string `json:"image_id"`
}

func (c CallerIdentity) String() string {
	if c.Kind == CallerKindPod {
		return fmt.Sprintf("%s/%s (%s)", c.Namespace, c.PodName, c.PodUID)
	}
	return fmt.Sprintf("%s (%s)", c.AppName, c.AppUUID)
}

var errUnknownCaller = errors.New("source address is not an application on a network instance of this device")

// resolveCaller maps a source IP to the application zedrouter assigned it
// to. A Kubernetes workload attached to a network instance (see
// docs/EVE-K-NETWORK-INSTANCES.md) has an AppNetworkStatus with KubeApp set;
// for it the pod, its service account and its image digests come from the
// Kubernetes API.
func (msrv *Msrv) resolveCaller(ctx context.Context, ip net.IP) (*CallerIdentity, error) {
	if ip == nil {
		return nil, errUnknownCaller
	}
	st := msrv.lookupAppNetworkStatusByAppIP(ip)
	if st == nil {
		return nil, errUnknownCaller
	}
	id := &CallerIdentity{
		Kind:       CallerKindAppInstance,
		AppUUID:    st.UUIDandVersion.UUID.String(),
		AppVersion: st.UUIDandVersion.Version,
		AppName:    st.DisplayName,
	}
	if st.KubeApp == nil {
		return id, nil
	}
	id.Kind = CallerKindPod
	id.Namespace = st.KubeApp.Namespace
	if err := msrv.addKubePodIdentity(ctx, id, st.KubeApp.OwnerName); err != nil {
		return nil, fmt.Errorf("identifying pod of %s/%s: %w",
			st.KubeApp.Namespace, st.KubeApp.OwnerName, err)
	}
	return id, nil
}
