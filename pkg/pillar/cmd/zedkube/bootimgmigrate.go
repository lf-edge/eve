// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"strings"
	"time"

	ctrd "github.com/containerd/containerd"
	ctrdnamespaces "github.com/containerd/containerd/namespaces"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sapitypes "k8s.io/apimachinery/pkg/types"
	virtv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
)

const (
	extBootImgBase   = "docker.io/lfedge/eve-external-boot-image:"
	extBootImgLatest = extBootImgBase + "latest"
	k3sCtrdSock      = "/run/containerd-user/containerd.sock"
	k3sCtrdNamespace = "k8s.io"
	ctrdCheckTimeout = 5 * time.Second
)

type bootImgMigrateState int

const (
	bootImgStateWaitReady bootImgMigrateState = iota // wait for image + KubeVirt (order-independent)
	bootImgStateMigrate                              // patch local VMIRSes
	bootImgStateDone                                 // stable final state
)

func (s bootImgMigrateState) String() string {
	switch s {
	case bootImgStateWaitReady:
		return "WaitReady"
	case bootImgStateMigrate:
		return "Migrate"
	case bootImgStateDone:
		return "Done"
	default:
		return "Unknown"
	}
}

// bootImgMigrator is a one-shot state machine that migrates VMIRSes on this
// node from versioned eve-external-boot-image tags to :latest.  It runs in the
// zedkube timer loop until it reaches Done.
//
// State transitions:
//
//	WaitReady → Migrate → Done
//
// WaitReady: poll (independently, in any order) until eve-external-boot-image:latest
//
//	is present in k3s containerd AND the KubeVirt CR reports Available.
//	imageReady and kubeVirtReady are cached once true so each condition is
//	only re-checked until it first succeeds.
//
// Migrate: patch all local VMIRSes (affinity hostname == z.nodeName) that still
//
//	reference a versioned tag.  Retried on partial failure.
//
// Done: nothing left to do.
type bootImgMigrator struct {
	state         bootImgMigrateState
	imageReady    bool
	kubeVirtReady bool
}

// step advances the state machine one tick. Called from the zedkube event loop.
// virtClient is injected so callers can supply a fake for testing.
func (m *bootImgMigrator) step(nodeName, namespace string, virtClient kubecli.KubevirtClient) {
	prev := m.state
	switch m.state {
	case bootImgStateWaitReady:
		if !m.imageReady {
			m.imageReady = extBootImgLatestPresent()
		}
		if !m.kubeVirtReady {
			m.kubeVirtReady = kubeVirtCondAvailable(virtClient)
		}
		if m.imageReady && m.kubeVirtReady {
			log.Noticef("bootImgMigrate: %s -> Migrate", prev)
			m.state = bootImgStateMigrate
		}

	case bootImgStateMigrate:
		done, err := migrateLocalVMIRSBootImages(nodeName, namespace, virtClient)
		if err != nil {
			log.Warnf("bootImgMigrate: migration error (will retry): %v", err)
			return
		}
		if done {
			log.Noticef("bootImgMigrate: %s -> Done", prev)
			m.state = bootImgStateDone
		}

	case bootImgStateDone:
		// stable final state
	}
}

// extBootImgLatestPresent returns true if eve-external-boot-image:latest is
// present in the k3s containerd image store (namespace k8s.io).
func extBootImgLatestPresent() bool {
	client, err := ctrd.New(k3sCtrdSock, ctrd.WithTimeout(ctrdCheckTimeout))
	if err != nil {
		return false
	}
	defer client.Close()
	ctx := ctrdnamespaces.WithNamespace(context.Background(), k3sCtrdNamespace)
	_, err = client.ImageService().Get(ctx, extBootImgLatest)
	return err == nil
}

// kubeVirtCondAvailable returns true when the KubeVirt CR reports the
// KubeVirtConditionAvailable condition as True.
func kubeVirtCondAvailable(virtClient kubecli.KubevirtClient) bool {
	ctx, cancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer cancel()
	kv, err := virtClient.KubeVirt("kubevirt").Get(ctx, "kubevirt", metav1.GetOptions{})
	if err != nil {
		return false
	}
	for _, cond := range kv.Status.Conditions {
		if cond.Type == virtv1.KubeVirtConditionAvailable && cond.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// migrateLocalVMIRSBootImages patches VMIRSes whose node affinity names this
// node and whose KernelBoot image is a versioned (non-:latest) external-boot
// image.  Returns (true, nil) when no such VMIRSes remain (or there were none).
// Returns (false, nil) if any patch failed; the caller should retry.
func migrateLocalVMIRSBootImages(nodeName, namespace string, virtClient kubecli.KubevirtClient) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer cancel()
	list, err := virtClient.ReplicaSet(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, err
	}

	patch := []byte(`{"spec":{"template":{"spec":{"domain":{"firmware":{"kernelBoot":{"container":{"image":"` +
		extBootImgLatest + `"}}}}}}}}`)

	anyFailed := false
	for i := range list.Items {
		vmirs := &list.Items[i]
		if vmirsAffinityNode(vmirs) != nodeName {
			continue
		}
		tmpl := vmirs.Spec.Template
		if tmpl == nil ||
			tmpl.Spec.Domain.Firmware == nil ||
			tmpl.Spec.Domain.Firmware.KernelBoot == nil ||
			tmpl.Spec.Domain.Firmware.KernelBoot.Container == nil {
			continue
		}
		img := tmpl.Spec.Domain.Firmware.KernelBoot.Container.Image
		if img == extBootImgLatest || !strings.HasPrefix(img, extBootImgBase) {
			continue
		}
		log.Noticef("bootImgMigrate: VMIRS %s: %s -> %s", vmirs.Name, img, extBootImgLatest)
		patchCtx, patchCancel := context.WithTimeout(context.Background(), kubeAPITimeout)
		_, merr := virtClient.ReplicaSet(namespace).Patch(
			patchCtx, vmirs.Name, k8sapitypes.MergePatchType, patch, metav1.PatchOptions{})
		patchCancel()
		if merr != nil {
			log.Warnf("bootImgMigrate: patch VMIRS %s: %v", vmirs.Name, merr)
			anyFailed = true
		}
	}
	return !anyFailed, nil
}

// vmirsAffinityNode extracts the kubernetes.io/hostname value from the EVE-set
// node affinity in a VMIRS template spec.  EVE encodes the owner node via
// setKubeAffinity using either preferredDuringSchedulingIgnoredDuringExecution
// or requiredDuringSchedulingIgnoredDuringExecution.  Returns "" if neither is
// present or the hostname matchExpression is absent.
func vmirsAffinityNode(vmirs *virtv1.VirtualMachineInstanceReplicaSet) string {
	if vmirs.Spec.Template == nil {
		return ""
	}
	aff := vmirs.Spec.Template.Spec.Affinity
	if aff == nil || aff.NodeAffinity == nil {
		return ""
	}
	na := aff.NodeAffinity
	for _, pref := range na.PreferredDuringSchedulingIgnoredDuringExecution {
		for _, expr := range pref.Preference.MatchExpressions {
			if expr.Key == "kubernetes.io/hostname" && len(expr.Values) > 0 {
				return expr.Values[0]
			}
		}
	}
	if req := na.RequiredDuringSchedulingIgnoredDuringExecution; req != nil {
		for _, term := range req.NodeSelectorTerms {
			for _, expr := range term.MatchExpressions {
				if expr.Key == "kubernetes.io/hostname" && len(expr.Values) > 0 {
					return expr.Values[0]
				}
			}
		}
	}
	return ""
}
