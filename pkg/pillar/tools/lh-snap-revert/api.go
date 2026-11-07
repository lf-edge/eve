// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	lh "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	lhclient "github.com/longhorn/longhorn-manager/k8s/pkg/client/clientset/versioned/typed/longhorn/v1beta2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	appsclient "k8s.io/client-go/kubernetes/typed/apps/v1"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	storageclient "k8s.io/client-go/kubernetes/typed/storage/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	longhornNamespace = "longhorn-system"
	// The revert action has no CRD, so it goes to the Longhorn REST API
	// through the API server service proxy.
	longhornProxyPath = "/api/v1/namespaces/" + longhornNamespace +
		"/services/longhorn-backend:manager/proxy"
)

var (
	vmiGVR   = schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachineinstances"}
	vmirsGVR = schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachineinstancereplicasets"}
)

// api is everything the tool reads or changes in the cluster. Lookups of a
// single object return (nil, nil) when the object does not exist only where
// noted.
type api interface {
	LonghornVersion(ctx context.Context) (string, error)
	PVC(ctx context.Context, ns, name string) (*corev1.PersistentVolumeClaim, error)
	PVCs(ctx context.Context, ns string) ([]corev1.PersistentVolumeClaim, error)
	PV(ctx context.Context, name string) (*corev1.PersistentVolume, error)
	// PVCUsers returns "kind/name" for every pod, VMIRS and VMI that
	// references the PVC.
	PVCUsers(ctx context.Context, ns, pvc string) ([]string, error)
	// CSIAttachments returns the nodes of storage.k8s.io VolumeAttachments
	// for the PV.
	CSIAttachments(ctx context.Context, pv string) ([]string, error)
	Volume(ctx context.Context, name string) (*lh.Volume, error)
	// VolumeAttachment returns (nil, nil) if the Longhorn VolumeAttachment
	// does not exist.
	VolumeAttachment(ctx context.Context, volume string) (*lh.VolumeAttachment, error)
	// PatchTicket adds or replaces the attachment ticket id, or removes it
	// when t is nil.
	PatchTicket(ctx context.Context, volume, id string, t *lh.AttachmentTicket) error
	// HoldRecurringJobs sets the recurring-job labels keys to disabled and
	// records them on the volume, or restores them when hold is false.
	HoldRecurringJobs(ctx context.Context, volume string, keys []string, hold bool) error
	Nodes(ctx context.Context) ([]lh.Node, error)
	Replicas(ctx context.Context, volume string) ([]lh.Replica, error)
	Snapshots(ctx context.Context, volume string) ([]lh.Snapshot, error)
	CreateSnapshot(ctx context.Context, volume, name string) error
	DeleteSnapshot(ctx context.Context, name string) error
	Revert(ctx context.Context, volume, snapshot string) error
}

// kubeAPI uses per-group clients rather than the full clientsets, which
// would link every API group into the binary.
type kubeAPI struct {
	core    coreclient.CoreV1Interface
	apps    appsclient.AppsV1Interface
	storage storageclient.StorageV1Interface
	lh      lhclient.LonghornV1beta2Interface
	dyn     dynamic.Interface
}

func newKubeAPI(kubeconfig string) (*kubeAPI, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig %s: %w", kubeconfig, err)
	}
	// The API server warns about Longhorn's finalizer name on every
	// snapshot create; that is noise for an operator.
	cfg.WarningHandler = rest.NoWarnings{}
	k := &kubeAPI{}
	if k.core, err = coreclient.NewForConfig(cfg); err != nil {
		return nil, err
	}
	if k.apps, err = appsclient.NewForConfig(cfg); err != nil {
		return nil, err
	}
	if k.storage, err = storageclient.NewForConfig(cfg); err != nil {
		return nil, err
	}
	if k.lh, err = lhclient.NewForConfig(cfg); err != nil {
		return nil, err
	}
	if k.dyn, err = dynamic.NewForConfig(cfg); err != nil {
		return nil, err
	}
	return k, nil
}

func (k *kubeAPI) LonghornVersion(ctx context.Context) (string, error) {
	ds, err := k.apps.DaemonSets(longhornNamespace).Get(ctx, "longhorn-manager", metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == "longhorn-manager" {
			return imageTag(c.Image), nil
		}
	}
	return "", errors.New("no longhorn-manager container in the longhorn-manager daemonset")
}

// imageTag returns the tag of an image reference, ignoring any digest.
func imageTag(image string) string {
	image, _, _ = strings.Cut(image, "@")
	i := strings.LastIndex(image, ":")
	if i < 0 || strings.Contains(image[i:], "/") {
		return ""
	}
	return image[i+1:]
}

func (k *kubeAPI) PVC(ctx context.Context, ns, name string) (*corev1.PersistentVolumeClaim, error) {
	return k.core.PersistentVolumeClaims(ns).Get(ctx, name, metav1.GetOptions{})
}

func (k *kubeAPI) PVCs(ctx context.Context, ns string) ([]corev1.PersistentVolumeClaim, error) {
	l, err := k.core.PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return l.Items, nil
}

func (k *kubeAPI) PV(ctx context.Context, name string) (*corev1.PersistentVolume, error) {
	return k.core.PersistentVolumes().Get(ctx, name, metav1.GetOptions{})
}

func (k *kubeAPI) PVCUsers(ctx context.Context, ns, pvc string) ([]string, error) {
	var users []string
	pods, err := k.core.Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, p := range pods.Items {
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == pvc {
				users = append(users, "pod/"+p.Name)
				break
			}
		}
	}
	for _, r := range []struct {
		gvr  schema.GroupVersionResource
		kind string
		path []string
	}{
		{vmirsGVR, "vmirs", []string{"spec", "template", "spec", "volumes"}},
		{vmiGVR, "vmi", []string{"spec", "volumes"}},
	} {
		l, err := k.dyn.Resource(r.gvr).Namespace(ns).List(ctx, metav1.ListOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, item := range l.Items {
			if usesClaim(item.Object, r.path, pvc) {
				users = append(users, r.kind+"/"+item.GetName())
			}
		}
	}
	return users, nil
}

// usesClaim reports whether the KubeVirt volume list at path references
// the PVC directly or through a DataVolume of the same name.
func usesClaim(obj map[string]interface{}, path []string, pvc string) bool {
	vols, _, _ := unstructured.NestedSlice(obj, path...)
	for _, v := range vols {
		m, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		if n, _, _ := unstructured.NestedString(m, "persistentVolumeClaim", "claimName"); n == pvc {
			return true
		}
		if n, _, _ := unstructured.NestedString(m, "dataVolume", "name"); n == pvc {
			return true
		}
	}
	return false
}

func (k *kubeAPI) CSIAttachments(ctx context.Context, pv string) ([]string, error) {
	l, err := k.storage.VolumeAttachments().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var nodes []string
	for _, va := range l.Items {
		if n := va.Spec.Source.PersistentVolumeName; n != nil && *n == pv {
			nodes = append(nodes, va.Spec.NodeName)
		}
	}
	return nodes, nil
}

func (k *kubeAPI) Volume(ctx context.Context, name string) (*lh.Volume, error) {
	return k.lh.Volumes(longhornNamespace).Get(ctx, name, metav1.GetOptions{})
}

func (k *kubeAPI) VolumeAttachment(ctx context.Context, volume string) (*lh.VolumeAttachment, error) {
	va, err := k.lh.VolumeAttachments(longhornNamespace).Get(ctx, volume, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	return va, err
}

func (k *kubeAPI) PatchTicket(ctx context.Context, volume, id string, t *lh.AttachmentTicket) error {
	data, err := ticketPatch(id, t)
	if err != nil {
		return err
	}
	_, err = k.lh.VolumeAttachments(longhornNamespace).
		Patch(ctx, volume, types.MergePatchType, data, metav1.PatchOptions{})
	return err
}

// ticketPatch builds a JSON merge patch that sets attachment ticket id to
// t, or deletes it when t is nil. Only the fields a client may set are sent.
func ticketPatch(id string, t *lh.AttachmentTicket) ([]byte, error) {
	var ticket interface{}
	if t != nil {
		ticket = map[string]interface{}{
			"id":         t.ID,
			"type":       t.Type,
			"nodeID":     t.NodeID,
			"parameters": t.Parameters,
		}
	}
	return json.Marshal(map[string]interface{}{
		"spec": map[string]interface{}{
			"attachmentTickets": map[string]interface{}{id: ticket},
		},
	})
}

func (k *kubeAPI) HoldRecurringJobs(ctx context.Context, volume string, keys []string, hold bool) error {
	data, err := holdPatch(keys, hold)
	if err != nil {
		return err
	}
	_, err = k.lh.Volumes(longhornNamespace).
		Patch(ctx, volume, types.MergePatchType, data, metav1.PatchOptions{})
	return err
}

func (k *kubeAPI) Nodes(ctx context.Context) ([]lh.Node, error) {
	l, err := k.lh.Nodes(longhornNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return l.Items, nil
}

func (k *kubeAPI) Replicas(ctx context.Context, volume string) ([]lh.Replica, error) {
	l, err := k.lh.Replicas(longhornNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var out []lh.Replica
	for _, r := range l.Items {
		if r.Spec.VolumeName == volume {
			out = append(out, r)
		}
	}
	return out, nil
}

func (k *kubeAPI) Snapshots(ctx context.Context, volume string) ([]lh.Snapshot, error) {
	l, err := k.lh.Snapshots(longhornNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var out []lh.Snapshot
	for _, s := range l.Items {
		if s.Spec.Volume == volume {
			out = append(out, s)
		}
	}
	return out, nil
}

func (k *kubeAPI) CreateSnapshot(ctx context.Context, volume, name string) error {
	s := &lh.Snapshot{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: longhornNamespace},
		Spec:       lh.SnapshotSpec{Volume: volume, CreateSnapshot: true},
	}
	_, err := k.lh.Snapshots(longhornNamespace).Create(ctx, s, metav1.CreateOptions{})
	return err
}

func (k *kubeAPI) DeleteSnapshot(ctx context.Context, name string) error {
	return k.lh.Snapshots(longhornNamespace).Delete(ctx, name, metav1.DeleteOptions{})
}

func (k *kubeAPI) Revert(ctx context.Context, volume, snapshot string) error {
	body, err := json.Marshal(map[string]string{"name": snapshot})
	if err != nil {
		return err
	}
	res := k.core.RESTClient().Post().
		AbsPath(longhornProxyPath, "v1", "volumes", volume).
		Param("action", "snapshotRevert").
		SetHeader("Content-Type", "application/json").
		Body(body).
		Do(ctx)
	raw, err := res.Raw()
	if err == nil {
		return nil
	}
	var status int
	res.StatusCode(&status)
	if status == 0 {
		return err
	}
	return fmt.Errorf("HTTP %d: %s", status, longhornMessage(raw, err))
}

// longhornMessage extracts the "message" field of a Longhorn error body,
// falling back to err.
func longhornMessage(body []byte, err error) string {
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil && e.Message != "" {
		return e.Message
	}
	return err.Error()
}
