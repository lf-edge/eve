// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	lh "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testVol = "pvc-1234"

// fakeAPI is an in-memory cluster. Attach and detach take effect at once.
// Like Longhorn v1.9.1, a snapshot of a detached volume attaches it with
// the frontend enabled, and one taken with the frontend disabled crashes
// the engine and never becomes ready.
type fakeAPI struct {
	version   string
	pvc       *corev1.PersistentVolumeClaim
	pv        *corev1.PersistentVolume
	users     []string
	vol       *lh.Volume
	va        *lh.VolumeAttachment
	snaps     []lh.Snapshot
	revertErr error
	detachErr error
	onRevert  func()
	slowSnap  bool // the first poll of a new snapshot shows a retry error
	stuckSnap bool // a new snapshot never becomes ready
	calls     []string
}

func newFake() *fakeAPI {
	return &fakeAPI{
		version: supportedLonghorn,
		pvc: &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "app-pvc-0", UID: "uid-1"},
			Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: testVol},
			Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
		},
		pv: &corev1.PersistentVolume{Spec: corev1.PersistentVolumeSpec{PersistentVolumeSource: corev1.PersistentVolumeSource{
			CSI: &corev1.CSIPersistentVolumeSource{Driver: longhornCSIDriver, VolumeHandle: testVol},
		}}},
		vol: &lh.Volume{
			ObjectMeta: metav1.ObjectMeta{Name: testVol, Labels: map[string]string{defaultGroupLabel: labelEnabled}},
			Status:     lh.VolumeStatus{State: lh.VolumeStateDetached},
		},
		va:    &lh.VolumeAttachment{},
		snaps: []lh.Snapshot{{ObjectMeta: metav1.ObjectMeta{Name: "target"}, Status: lh.SnapshotStatus{ReadyToUse: true}}},
	}
}

func (f *fakeAPI) LonghornVersion(context.Context) (string, error) { return f.version, nil }
func (f *fakeAPI) PVC(context.Context, string, string) (*corev1.PersistentVolumeClaim, error) {
	return f.pvc.DeepCopy(), nil
}
func (f *fakeAPI) PVCs(context.Context, string) ([]corev1.PersistentVolumeClaim, error) {
	return []corev1.PersistentVolumeClaim{*f.pvc}, nil
}
func (f *fakeAPI) PV(context.Context, string) (*corev1.PersistentVolume, error) {
	return f.pv.DeepCopy(), nil
}
func (f *fakeAPI) PVCUsers(context.Context, string, string) ([]string, error) { return f.users, nil }
func (f *fakeAPI) CSIAttachments(context.Context, string) ([]string, error)   { return nil, nil }
func (f *fakeAPI) Volume(context.Context, string) (*lh.Volume, error)         { return f.vol.DeepCopy(), nil }
func (f *fakeAPI) VolumeAttachment(context.Context, string) (*lh.VolumeAttachment, error) {
	out := f.va.DeepCopy()
	for _, s := range f.snaps {
		id := string(lh.AttacherTypeSnapshotController) + "-" + s.Name
		if s.Status.ReadyToUse && f.va.Spec.AttachmentTickets[id] != nil {
			delete(f.va.Spec.AttachmentTickets, id)
			f.vol.Status = lh.VolumeStatus{State: lh.VolumeStateDetached}
		}
	}
	return out, nil
}
func (f *fakeAPI) HoldRecurringJobs(_ context.Context, _ string, keys []string, hold bool) error {
	f.calls = append(f.calls, map[bool]string{true: "hold", false: "release"}[hold])
	v, held := labelEnabled, ""
	if hold {
		v, held = labelDisabled, strings.Join(keys, ",")
	}
	for _, k := range keys {
		f.vol.Labels[k] = v
	}
	f.vol.Annotations = map[string]string{heldAnnotation: held}
	return nil
}
func (f *fakeAPI) Nodes(context.Context) ([]lh.Node, error) {
	n := lh.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}
	n.Status.Conditions = []lh.Condition{{Type: lh.NodeConditionTypeReady, Status: lh.ConditionStatusTrue}}
	return []lh.Node{n}, nil
}
func (f *fakeAPI) Replicas(context.Context, string) ([]lh.Replica, error) { return nil, nil }
func (f *fakeAPI) Snapshots(context.Context, string) ([]lh.Snapshot, error) {
	out := append([]lh.Snapshot(nil), f.snaps...)
	for i := range f.snaps {
		if f.snaps[i].Status.Error != "" && !f.vol.Status.FrontendDisabled && !f.stuckSnap {
			f.snaps[i].Status = lh.SnapshotStatus{ReadyToUse: true}
		}
	}
	return out, nil
}

func (f *fakeAPI) PatchTicket(ctx context.Context, _, id string, t *lh.AttachmentTicket) error {
	if t == nil {
		f.calls = append(f.calls, "detach")
		if err := ctx.Err(); err != nil {
			return err
		}
		if f.detachErr != nil {
			return f.detachErr
		}
		f.va.Spec.AttachmentTickets = nil
		f.vol.Status = lh.VolumeStatus{State: lh.VolumeStateDetached}
		return nil
	}
	f.calls = append(f.calls, "attach")
	// The tool must add its ticket only to an idle volume. The ticket of a
	// snapshot that just became ready stays until the next poll.
	if n := len(f.va.Spec.AttachmentTickets); n > 0 {
		return fmt.Errorf("fake: %d other tickets still hold the volume", n)
	}
	f.va.Spec.AttachmentTickets = map[string]*lh.AttachmentTicket{id: t}
	f.va.Status.AttachmentTicketStatuses = map[string]*lh.AttachmentTicketStatus{id: {Satisfied: true}}
	f.vol.Status = lh.VolumeStatus{State: lh.VolumeStateAttached, CurrentNodeID: t.NodeID,
		FrontendDisabled: t.Parameters[lh.AttachmentParameterDisableFrontend] == "true"}
	return nil
}

func (f *fakeAPI) CreateSnapshot(_ context.Context, _, name string) error {
	f.calls = append(f.calls, "snapshot")
	st := lh.SnapshotStatus{ReadyToUse: true}
	if f.slowSnap || f.stuckSnap || f.vol.Status.FrontendDisabled {
		st = lh.SnapshotStatus{Error: "failed to take snapshot because the volume engine is not running"}
	}
	if f.vol.Status.State == lh.VolumeStateDetached {
		id := string(lh.AttacherTypeSnapshotController) + "-" + name
		f.va.Spec.AttachmentTickets = map[string]*lh.AttachmentTicket{
			id: {ID: id, Type: lh.AttacherTypeSnapshotController}}
		f.vol.Status = lh.VolumeStatus{State: lh.VolumeStateAttached}
	}
	f.snaps = append(f.snaps, lh.Snapshot{ObjectMeta: metav1.ObjectMeta{Name: name}, Status: st})
	return nil
}

func (f *fakeAPI) DeleteSnapshot(_ context.Context, name string) error {
	f.calls = append(f.calls, "delete "+name)
	return nil
}

func (f *fakeAPI) Revert(ctx context.Context, _, _ string) error {
	f.calls = append(f.calls, "revert")
	if f.onRevert != nil {
		f.onRevert()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.revertErr
}

func testOpts() *revertOpts {
	return &revertOpts{
		namespace: "eve-kube-app", pvc: "app-pvc-0", snapshot: "target", yes: true,
		timeout: 200 * time.Millisecond, poll: time.Millisecond,
		out: &bytes.Buffer{}, now: time.Now,
	}
}

func TestRevertSuccess(t *testing.T) {
	f := newFake()
	f.slowSnap = true // Longhorn's retry error must not abort the run
	if err := runRevert(context.Background(), f, testOpts()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"hold", "snapshot", "attach", "revert", "detach", "release"}; !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %v, want %v", f.calls, want)
	}
	if f.vol.Labels[defaultGroupLabel] != labelEnabled || len(heldLabels(f.vol)) > 0 {
		t.Fatalf("recurring jobs not restored: %v %v", f.vol.Labels, f.vol.Annotations)
	}
}

func TestPreflightRefusesWithoutChanges(t *testing.T) {
	tests := map[string]func(f *fakeAPI){
		"tested only with":      func(f *fakeAPI) { f.version = "v1.6.3" },
		"in use by vmi/app":     func(f *fakeAPI) { f.users = []string{"vmi/app"} },
		"Longhorn is detaching": func(f *fakeAPI) { f.vol.Status.State = lh.VolumeStateAttached },
		"cannot purge it": func(f *fakeAPI) {
			f.vol.Status.State = lh.VolumeStateAttached
			f.va.Spec.AttachmentTickets = map[string]*lh.AttachmentTicket{
				"snapshot-controller-old": {Type: lh.AttacherTypeSnapshotController}}
			f.snaps = append(f.snaps, lh.Snapshot{
				ObjectMeta: metav1.ObjectMeta{Name: "old", DeletionTimestamp: &metav1.Time{}},
				Status:     lh.SnapshotStatus{MarkRemoved: true, Children: map[string]bool{"a": true, "b": true}}})
		},
		"not ready":          func(f *fakeAPI) { f.snaps[0].Status.ReadyToUse = false },
		"previous run left":  func(f *fakeAPI) { f.va.Spec.AttachmentTickets = map[string]*lh.AttachmentTicket{ticketID: {}} },
		"not a Longhorn vol": func(f *fakeAPI) { f.pv.Spec.CSI.Driver = "other" },
		"undo the hold":      func(f *fakeAPI) { f.pvc.Labels = map[string]string{sourceLabel: labelEnabled} },
	}
	for want, mutate := range tests {
		f := newFake()
		mutate(f)
		err := runRevert(context.Background(), f, testOpts())
		if err == nil || !strings.Contains(err.Error(), want) || len(f.calls) != 0 {
			t.Errorf("%s: err %v, calls %v", want, err, f.calls)
		}
	}
}

func TestIgnoreLonghornVersion(t *testing.T) {
	f := newFake()
	f.version = "v1.10.1"
	o := testOpts()
	o.ignoreVersion = true
	if err := runRevert(context.Background(), f, o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(o.out.(*bytes.Buffer).String(), "Warning: running Longhorn version") {
		t.Fatal("no version warning")
	}
}

func TestFailedRevertReleasesVolume(t *testing.T) {
	f := newFake()
	f.revertErr = errors.New("HTTP 500: failed to revert snapshot")
	err := runRevert(context.Background(), f, testOpts())
	var ae *afterAttachError
	if !errors.As(err, &ae) || ae.reverted != "unknown" {
		t.Fatalf("err = %v", err)
	}
	if want := []string{"hold", "snapshot", "attach", "revert", "detach", "release"}; !reflect.DeepEqual(f.calls, want) ||
		f.vol.Status.State != lh.VolumeStateDetached {
		t.Fatalf("volume not released: calls %v", f.calls)
	}
}

func TestPendingSafetySnapshotNamed(t *testing.T) {
	f := newFake()
	f.stuckSnap = true
	o := testOpts()
	err := runRevert(context.Background(), f, o)
	var ae *afterAttachError
	if err == nil || errors.As(err, &ae) {
		t.Fatalf("want exit 1, got %v", err)
	}
	if want := []string{"hold", "snapshot", "release"}; !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %v, want %v", f.calls, want)
	}
	if out := o.out.(*bytes.Buffer).String(); !strings.Contains(out, "delete snapshots.longhorn.io "+safetyPrefix) {
		t.Fatalf("no delete command for the pending snapshot:\n%s", out)
	}
}

func TestCtrlCDoesNotCancelRevert(t *testing.T) {
	f := newFake()
	ctx, cancel := context.WithCancel(context.Background())
	f.onRevert = cancel
	err := runRevert(ctx, f, testOpts())
	var ae *afterAttachError
	if !errors.As(err, &ae) || ae.reverted != "yes" {
		t.Fatalf("want exit 2 with reverted yes, got %v", err)
	}
	if f.calls[len(f.calls)-1] != "release" || f.vol.Status.State != lh.VolumeStateDetached {
		t.Fatalf("volume not released after Ctrl-C: calls %v", f.calls)
	}
}

func TestFailedDetachKeepsHold(t *testing.T) {
	f := newFake()
	f.revertErr = errors.New("HTTP 500")
	f.detachErr = errors.New("conflict")
	err := runRevert(context.Background(), f, testOpts())
	var ae *afterAttachError
	if !errors.As(err, &ae) || ae.reverted != "unknown" {
		t.Fatalf("err = %v", err)
	}
	// The volume may still be attached, so the jobs must stay held.
	if f.calls[len(f.calls)-1] != "detach" || f.vol.Labels[defaultGroupLabel] != labelDisabled {
		t.Fatalf("hold released while attached: calls %v labels %v", f.calls, f.vol.Labels)
	}
}

func TestLabelsToHold(t *testing.T) {
	vol := func(labels, ann map[string]string) *lh.Volume {
		return &lh.Volume{ObjectMeta: metav1.ObjectMeta{Labels: labels, Annotations: ann}}
	}
	gold := groupLabelPrefix + "gold"
	tests := []struct {
		name string
		vol  *lh.Volume
		want []string
	}{
		{"no labels: default group", vol(nil, nil), []string{defaultGroupLabel}},
		{"only source: no group", vol(map[string]string{sourceLabel: labelEnabled}, nil), []string{}},
		{"only enabled ones", vol(map[string]string{defaultGroupLabel: labelDisabled, gold: labelEnabled}, nil), []string{gold}},
		{"left held by a run", vol(map[string]string{defaultGroupLabel: labelDisabled},
			map[string]string{heldAnnotation: defaultGroupLabel}), []string{defaultGroupLabel}},
	}
	for _, tt := range tests {
		if got := labelsToHold(tt.vol); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestListAndCleanupOldBranch(t *testing.T) {
	snap := func(name, parent, created string, children ...string) lh.Snapshot {
		s := lh.Snapshot{ObjectMeta: metav1.ObjectMeta{Name: name},
			Status: lh.SnapshotStatus{Parent: parent, CreationTime: created, ReadyToUse: true, Children: map[string]bool{}}}
		for _, c := range children {
			s.Status.Children[c] = true
		}
		return s
	}
	x := snap("x", "", "1", "a", "c")
	x.DeletionTimestamp, x.Status.MarkRemoved = &metav1.Time{}, true
	f := newFake()
	// n is a recurring snapshot that the engine has not reported yet.
	n := lh.Snapshot{ObjectMeta: metav1.ObjectMeta{Name: "n"}}
	f.snaps = []lh.Snapshot{x, snap("a", "x", "2", "s"), snap("s", "a", "3"),
		snap("c", "x", "4", volumeHead), n}
	var out bytes.Buffer
	if err := listSnapshots(context.Background(), f, "eve-kube-app", "app-pvc-0", &out); err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + out.String())
	for _, want := range []string{"2 children, cannot be purged", "creating", "\n|- a ", "\n|  s ", "\n`- c ", "\n   volume-head "} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
	if !strings.Contains(out.String(), "old branch, ready") {
		t.Error("old branch not marked")
	}

	f.vol.Status.State = lh.VolumeStateAttached
	o := testOpts()
	if err := runCleanup(context.Background(), f, o); err != nil {
		t.Fatal(err)
	}
	if want := []string{"delete a", "delete s"}; !reflect.DeepEqual(f.calls, want) {
		t.Errorf("cleanup calls = %v, want %v", f.calls, want)
	}
}
