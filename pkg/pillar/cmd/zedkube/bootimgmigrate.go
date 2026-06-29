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
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
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
//	only re-checked until it first succeeds.  nodeName must also be known
//	(non-empty) before we leave this state: the migration is scoped by
//	affinity == nodeName, so advancing with an empty nodeName would skip
//	every VMIRS and latch to Done having migrated nothing.
//
// Migrate: patch all local VMIRSes (affinity hostname == nodeName) that still
//
//	reference a versioned tag, then force-delete their VMIs still running a
//	versioned tag so the ReplicaSet recreates them from the patched template
//	(patching a VMIRS template does not roll its existing VMIs).  Retried until
//	no local VMIRS template and no local VMI reference a versioned tag.
//
// Done: nothing left to do.
//
// Timing note: this migration races the descheduler (descheduler.go).  In a
// rolling upgrade the descheduler on the just-upgraded (designated) node can
// evict an app from a surviving node and reschedule it here before this machine
// patches the VMIRS.  The new pod then fails with ErrImageNeverPull because its
// versioned tag was deleted by cleanup_old_external_boot_images.  The Migrate
// step recovers this deterministically by deleting the stale VMI itself (see
// deleteStaleBootImgVMIs) rather than depending on checkStuckPendingVMI, whose
// bounded force-delete budget can be exhausted recreating old-tag VMIs while
// this machine is still in WaitReady waiting for KubeVirt to report Available.
// To keep the exposure window small, step() collapses WaitReady → Migrate into
// a single tick once both readiness conditions are met, rather than spending a
// tick per transition.
type bootImgMigrator struct {
	state         bootImgMigrateState
	imageReady    bool
	kubeVirtReady bool
}

// isDone reports whether the migrator has reached its terminal state, so the
// caller can skip building a kubevirt client (and re-reading kubeconfig) on
// every tick once there is no work left.
func (m *bootImgMigrator) isDone() bool {
	return m.state == bootImgStateDone
}

// step advances the state machine as far as it can in one tick, stopping when a
// state makes no further progress (waiting on an external condition or a retry).
// Called from the zedkube event loop; virtClient is injected so callers can
// supply a fake for testing.
func (m *bootImgMigrator) step(nodeName, namespace string, virtClient kubecli.KubevirtClient) {
	for {
		prev := m.state
		switch m.state {
		case bootImgStateWaitReady:
			// Scope the migration to this node by affinity, so nodeName must be
			// known first; an empty nodeName means EdgeNodeInfo has not been
			// received yet, so stay put rather than advance and skip everything.
			if nodeName == "" {
				return
			}
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
			return
		}
		if m.state == prev {
			// No progress this tick; wait for the next one.
			return
		}
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
// image, then deletes any of their VMIs still running a versioned tag so the
// ReplicaSet recreates them from the migrated template.  Returns (true, nil)
// when no local VMIRS template and no local VMI reference a versioned tag any
// more (or there were none).  Returns (false, nil) if a patch failed or a stale
// VMI was (re)deleted this call; the caller should retry.
func migrateLocalVMIRSBootImages(nodeName, namespace string, virtClient kubecli.KubevirtClient) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer cancel()
	list, err := virtClient.ReplicaSet(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, err
	}

	patch := []byte(`{"spec":{"template":{"spec":{"domain":{"firmware":{"kernelBoot":{"container":{"image":"` +
		extBootImgLatest + `"}}}}}}}}`)

	// localVMIRS collects the names of every VMIRS scheduled to this node so we
	// can find and replace their stale VMIs below.  Membership is not
	// conditional on patching: a VMIRS whose template is already :latest can
	// still own a VMI that predates the migration.
	localVMIRS := make(map[string]struct{})
	anyFailed := false
	for i := range list.Items {
		vmirs := &list.Items[i]
		if vmirsAffinityNode(vmirs) != nodeName {
			continue
		}
		localVMIRS[vmirs.Name] = struct{}{}
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

	// Patching the VMIRS template does not roll existing VMIs: KubeVirt keeps a
	// VMI on the template it was created from, so a VMI created from the old
	// (versioned) tag stays wedged in ErrImageNeverPull because that tag was
	// pruned by cluster-init's cleanup_old_external_boot_images on upgrade.
	// Delete those stale VMIs so the ReplicaSet recreates them from the now
	// :latest template.  We cannot rely on checkStuckPendingVMI for this: its
	// force-delete budget (pendingVMIMaxDeletes) can be exhausted recreating
	// old-tag VMIs while this migrator is still blocked in WaitReady waiting for
	// KubeVirt to report Available.
	staleVMIs, derr := deleteStaleBootImgVMIs(namespace, localVMIRS, virtClient)
	if derr != nil {
		return false, derr
	}

	// Stay out of Done while a stale VMI was just (re)deleted: next tick
	// re-checks until the ReplicaSet has recreated it from :latest.
	return !anyFailed && !staleVMIs, nil
}

// deleteStaleBootImgVMIs force-deletes VMIs owned by one of the given (local)
// VMIRSes whose KernelBoot image still references a versioned external-boot tag,
// so the owning ReplicaSet recreates them from the migrated :latest template.
// Returns true if any such VMI was found (and a delete attempted) this call, so
// the caller keeps retrying until none remain.  A VMI recreated from the
// migrated template carries :latest and is skipped, so this self-terminates.
func deleteStaleBootImgVMIs(namespace string, localVMIRS map[string]struct{}, virtClient kubecli.KubevirtClient) (bool, error) {
	if len(localVMIRS) == 0 {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer cancel()
	vmiList, err := virtClient.VirtualMachineInstance(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	anyStale := false
	for i := range vmiList.Items {
		vmi := &vmiList.Items[i]
		if len(vmi.OwnerReferences) == 0 {
			continue
		}
		if _, ok := localVMIRS[vmi.OwnerReferences[0].Name]; !ok {
			continue
		}
		fw := vmi.Spec.Domain.Firmware
		if fw == nil || fw.KernelBoot == nil || fw.KernelBoot.Container == nil {
			continue
		}
		img := fw.KernelBoot.Container.Image
		if img == extBootImgLatest || !strings.HasPrefix(img, extBootImgBase) {
			continue
		}
		anyStale = true
		log.Noticef("bootImgMigrate: VMI %s references stale %s; force-deleting so ReplicaSet recreates from %s",
			vmi.Name, img, extBootImgLatest)
		if err := kubeapi.TryFastDeleteVmi(log, virtClient, vmi.Name); err != nil {
			log.Warnf("bootImgMigrate: delete stale VMI %s: %v", vmi.Name, err)
		}
	}
	return anyStale, nil
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
