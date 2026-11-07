// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	lh "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	corev1 "k8s.io/api/core/v1"
)

const (
	supportedLonghorn = "v1.9.1"
	longhornCSIDriver = "driver.longhorn.io"
	ticketID          = "lh-snap-revert"
	safetyPrefix      = "lh-snap-revert-"
	apiCallTimeout    = 30 * time.Second
)

var errAborted = errors.New("aborted by user, nothing changed")

// afterAttachError is a failure after the tool asked Longhorn to attach the
// volume. Reverted is "no", "yes" or "unknown".
type afterAttachError struct {
	err      error
	reverted string
}

func (e *afterAttachError) Error() string { return e.err.Error() }
func (e *afterAttachError) Unwrap() error { return e.err }

type revertOpts struct {
	namespace, pvc, snapshot, node string
	noSafety, ignoreVersion        bool
	yes, dryRun                    bool
	timeout, poll                  time.Duration
	in                             io.Reader
	out                            io.Writer
	now                            func() time.Time
}

type plan struct {
	pvcUID, pv, volume, node string
	snapshotCreated          string
	holdKeys                 []string
}

func runRevert(ctx context.Context, a api, o *revertOpts) error {
	pctx, cancel := context.WithTimeout(ctx, o.timeout)
	p, err := preflight(pctx, a, o)
	cancel()
	if err != nil {
		return err
	}
	printPlan(o, p)
	if o.dryRun {
		fmt.Fprintln(o.out, "Dry run: nothing changed.")
		return nil
	}
	if !o.yes && !confirm(ctx, o) {
		return errAborted
	}
	return execute(ctx, a, o, p)
}

// preflight checks everything it can before changing anything.
func preflight(ctx context.Context, a api, o *revertOpts) (*plan, error) {
	v, err := a.LonghornVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("read Longhorn version: %w", err)
	}
	if v != supportedLonghorn {
		if !o.ignoreVersion {
			return nil, fmt.Errorf("running Longhorn version is %q, this tool is tested only with %s; "+
				"to run anyway, pass --ignore-longhorn-version", v, supportedLonghorn)
		}
		fmt.Fprintf(o.out, "Warning: running Longhorn version is %q, this tool is tested only with %s. "+
			"Continuing because of --ignore-longhorn-version.\n", v, supportedLonghorn)
	}
	pvc, volName, err := resolveVolume(ctx, a, o.namespace, o.pvc)
	if err != nil {
		return nil, err
	}
	if pvc.Labels[sourceLabel] == labelEnabled {
		return nil, fmt.Errorf("PVC %s has %s=%s, so Longhorn copies its recurring job labels "+
			"to the volume and would undo the hold; remove that label first", o.pvc, sourceLabel, labelEnabled)
	}
	users, err := a.PVCUsers(ctx, o.namespace, o.pvc)
	if err != nil {
		return nil, fmt.Errorf("find users of PVC %s: %w", o.pvc, err)
	}
	if len(users) > 0 {
		return nil, fmt.Errorf("PVC %s is in use by %s; deactivate the app first",
			o.pvc, strings.Join(users, ", "))
	}
	vol, err := a.Volume(ctx, volName)
	if err != nil {
		return nil, fmt.Errorf("get Longhorn volume %s: %w", volName, err)
	}
	va, err := a.VolumeAttachment(ctx, volName)
	if err != nil {
		return nil, fmt.Errorf("get Longhorn VolumeAttachment %s: %w", volName, err)
	}
	if vol.Status.State != lh.VolumeStateDetached || (va != nil && len(va.Spec.AttachmentTickets) > 0) {
		return nil, attachedError(ctx, a, o.pvc, vol, va)
	}
	nodes, err := a.CSIAttachments(ctx, pvc.Spec.VolumeName)
	if err != nil {
		return nil, fmt.Errorf("list CSI VolumeAttachments: %w", err)
	}
	if len(nodes) > 0 {
		return nil, fmt.Errorf("CSI VolumeAttachment for PV %s still exists on %s",
			pvc.Spec.VolumeName, strings.Join(nodes, ", "))
	}
	snap, err := findSnapshot(ctx, a, volName, o.snapshot)
	if err != nil {
		return nil, err
	}
	node, err := chooseNode(ctx, a, volName, o.node)
	if err != nil {
		return nil, err
	}
	return &plan{
		pvcUID:          string(pvc.UID),
		pv:              pvc.Spec.VolumeName,
		volume:          volName,
		node:            node,
		snapshotCreated: snap.Status.CreationTime,
		holdKeys:        labelsToHold(vol),
	}, nil
}

// resolveVolume returns the PVC and the name of the Longhorn volume behind it.
func resolveVolume(ctx context.Context, a api, ns, name string) (*corev1.PersistentVolumeClaim, string, error) {
	pvc, err := a.PVC(ctx, ns, name)
	if err != nil {
		return nil, "", fmt.Errorf("get PVC %s/%s: %w", ns, name, err)
	}
	if pvc.Status.Phase != corev1.ClaimBound || pvc.Spec.VolumeName == "" {
		return nil, "", fmt.Errorf("PVC %s/%s is not Bound", ns, name)
	}
	pv, err := a.PV(ctx, pvc.Spec.VolumeName)
	if err != nil {
		return nil, "", fmt.Errorf("get PV %s: %w", pvc.Spec.VolumeName, err)
	}
	if pv.Spec.CSI == nil || pv.Spec.CSI.Driver != longhornCSIDriver || pv.Spec.CSI.VolumeHandle == "" {
		return nil, "", fmt.Errorf("PV %s is not a Longhorn volume", pv.Name)
	}
	return pvc, pv.Spec.CSI.VolumeHandle, nil
}

func findSnapshot(ctx context.Context, a api, volume, name string) (*lh.Snapshot, error) {
	snaps, err := a.Snapshots(ctx, volume)
	if err != nil {
		return nil, fmt.Errorf("list snapshots of %s: %w", volume, err)
	}
	for i := range snaps {
		s := &snaps[i]
		if s.Name != name {
			continue
		}
		switch {
		case s.Status.MarkRemoved:
			return nil, fmt.Errorf("snapshot %s is marked for removal", name)
		case !s.Status.ReadyToUse:
			return nil, fmt.Errorf("snapshot %s is not ready to use", name)
		}
		return s, nil
	}
	return nil, fmt.Errorf("snapshot %s not found on volume %s", name, volume)
}

// chooseNode returns the node to attach to: the requested one, else a Ready
// node holding a replica of the volume, else any Ready node.
func chooseNode(ctx context.Context, a api, volume, want string) (string, error) {
	nodes, err := a.Nodes(ctx)
	if err != nil {
		return "", fmt.Errorf("list Longhorn nodes: %w", err)
	}
	ready := map[string]bool{}
	var readyNames []string
	for _, n := range nodes {
		if nodeReady(n) {
			ready[n.Name] = true
			readyNames = append(readyNames, n.Name)
		}
	}
	sort.Strings(readyNames)
	if want != "" {
		if !ready[want] {
			return "", fmt.Errorf("node %q is not a Ready Longhorn node; Ready nodes: %s",
				want, strings.Join(readyNames, ", "))
		}
		return want, nil
	}
	reps, err := a.Replicas(ctx, volume)
	if err != nil {
		return "", fmt.Errorf("list replicas of %s: %w", volume, err)
	}
	var withReplica []string
	for _, r := range reps {
		if ready[r.Spec.NodeID] {
			withReplica = append(withReplica, r.Spec.NodeID)
		}
	}
	sort.Strings(withReplica)
	switch {
	case len(withReplica) > 0:
		return withReplica[0], nil
	case len(readyNames) > 0:
		return readyNames[0], nil
	}
	return "", errors.New("no Ready Longhorn node to attach the volume to")
}

func nodeReady(n lh.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == lh.NodeConditionTypeReady {
			return c.Status == lh.ConditionStatusTrue
		}
	}
	return false
}

func printPlan(o *revertOpts, p *plan) {
	fmt.Fprintf(o.out, "Revert plan\n")
	fmt.Fprintf(o.out, "  PVC:       %s/%s (UID %s, kept)\n", o.namespace, o.pvc, p.pvcUID)
	fmt.Fprintf(o.out, "  Volume:    %s (PV %s, kept)\n", p.volume, p.pv)
	fmt.Fprintf(o.out, "  Snapshot:  %s (created %s)\n", o.snapshot, p.snapshotCreated)
	fmt.Fprintf(o.out, "  Node:      %s\n", p.node)
	fmt.Fprintf(o.out, "  Safety-net snapshot: %t\n", !o.noSafety)
	fmt.Fprintf(o.out, "  Recurring jobs held: %s\n", strings.Join(p.holdKeys, ", "))
	fmt.Fprintln(o.out, "Data written to the volume after the snapshot will be lost.")
}

// confirm returns false on anything but "yes", and on Ctrl-C at the prompt.
func confirm(ctx context.Context, o *revertOpts) bool {
	fmt.Fprint(o.out, "Type yes to continue: ")
	answer := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(o.in).ReadString('\n')
		answer <- line
	}()
	select {
	case <-ctx.Done():
		fmt.Fprintln(o.out)
		return false
	case line := <-answer:
		return strings.TrimSpace(line) == "yes" && ctx.Err() == nil
	}
}

func execute(ctx context.Context, a api, o *revertOpts, p *plan) (retErr error) {
	// A failed patch may still have been applied, so each flag is set before
	// its patch. attached implies held. touched selects exit code 2.
	held, attached, touched := false, false, false
	reverted := "no"
	defer func() {
		if !held {
			return
		}
		fmt.Fprintln(o.out, "==> Cleanup (a second Ctrl-C stops it and leaves the volume as it is)")
		if attached {
			cctx, cancel := context.WithTimeout(context.Background(), o.timeout)
			err := detach(cctx, a, o, p.volume)
			cancel()
			if err != nil {
				fmt.Fprintf(o.out, "Cleanup failed: %v\nRelease the volume, then restore its recurring jobs:\n  %s\n  %s\n",
					err, manualDetachCmd(p.volume), manualReleaseCmd(p.volume, p.holdKeys))
				retErr = &afterAttachError{err: retErr, reverted: reverted}
				return
			}
		}
		cctx, cancel := context.WithTimeout(context.Background(), o.timeout)
		defer cancel()
		if err := release(cctx, a, p); err != nil {
			fmt.Fprintf(o.out, "Cleanup failed: %v\nRestore the recurring jobs of the volume:\n  %s\n",
				err, manualReleaseCmd(p.volume, p.holdKeys))
		}
		if touched {
			retErr = &afterAttachError{err: retErr, reverted: reverted}
		}
	}()

	step(o, 1, "Hold recurring jobs on %s", p.volume)
	held = true
	if err := callAPI(ctx, func(c context.Context) error {
		return a.HoldRecurringJobs(c, p.volume, p.holdKeys, true)
	}); err != nil {
		return fmt.Errorf("hold recurring jobs: %w", err)
	}

	// Snapshot before attaching: the Longhorn v1.9.1 engine crashes on a
	// snapshot while its frontend is disabled, and a revert needs it
	// disabled. Longhorn's snapshot controller attaches the detached volume
	// with the frontend enabled. The tool's higher-priority ticket would
	// disable it, so it is added only once the volume is idle.
	safety := ""
	if !o.noSafety {
		safety = safetyPrefix + o.now().UTC().Format("20060102-150405")
		step(o, 2, "Create safety-net snapshot %s", safety)
		// Longhorn keeps retrying a pending snapshot, which blocks the next run.
		pending := func(err error) error {
			fmt.Fprintf(o.out, "The safety-net snapshot may still be pending. Delete it before the next run:\n  %s\n",
				deleteSnapshotCmd(safety))
			return err
		}
		if err := callAPI(ctx, func(c context.Context) error {
			return a.CreateSnapshot(c, p.volume, safety)
		}); err != nil {
			return pending(fmt.Errorf("create safety-net snapshot: %w", err))
		}
		if err := waitFor(ctx, o, "safety-net snapshot", snapshotReadyCond(a, p.volume, safety)); err != nil {
			return pending(err)
		}
		if err := waitFor(ctx, o, "detach after snapshot", idleCond(a, p.volume)); err != nil {
			return err
		}
	}

	step(o, 3, "Attach %s to %s with the frontend disabled", p.volume, p.node)
	ticket := &lh.AttachmentTicket{
		ID:         ticketID,
		Type:       lh.AttacherTypeLonghornAPI,
		NodeID:     p.node,
		Parameters: map[string]string{lh.AttachmentParameterDisableFrontend: "true"},
	}
	attached, touched = true, true
	if err := callAPI(ctx, func(c context.Context) error {
		return a.PatchTicket(c, p.volume, ticketID, ticket)
	}); err != nil {
		return fmt.Errorf("add attachment ticket: %w", err)
	}
	if err := waitFor(ctx, o, "attach", attachedCond(a, p)); err != nil {
		return err
	}

	step(o, 4, "Re-check the recurring job hold and the target snapshot")
	if err := callAPI(ctx, func(c context.Context) error {
		vol, err := a.Volume(c, p.volume)
		if err != nil {
			return err
		}
		if l := enabledRecurringLabels(vol); len(l) > 0 {
			return fmt.Errorf("recurring job labels were enabled again on %s: %s", p.volume, strings.Join(l, ", "))
		}
		_, err = findSnapshot(c, a, p.volume, o.snapshot)
		return err
	}); err != nil {
		return err
	}

	step(o, 5, "Revert %s to %s", p.volume, o.snapshot)
	// Longhorn reports every failure as HTTP 500, also engine errors after
	// the revert started, so a failed call leaves the outcome unknown.
	// Longhorn keeps reverting if the client goes away, so Ctrl-C must not
	// cancel this call and let cleanup detach mid-revert.
	reverted = "unknown"
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), o.timeout)
	err := a.Revert(rctx, p.volume, o.snapshot)
	cancel()
	if err != nil {
		return fmt.Errorf("revert: %w", err)
	}
	reverted = "yes"

	step(o, 6, "Detach %s and restore its recurring jobs", p.volume)
	if err := detach(ctx, a, o, p.volume); err != nil {
		return err
	}
	attached = false
	if err := release(ctx, a, p); err != nil {
		return err
	}
	held = false

	step(o, 7, "Verify the PVC")
	if err := verifyPVC(ctx, a, o, p); err != nil {
		return &afterAttachError{err: err, reverted: reverted}
	}
	fmt.Fprintf(o.out, "\nReverted %s to %s.\n", p.volume, o.snapshot)
	if safety != "" {
		fmt.Fprintf(o.out, "To undo the revert, revert to %s.\n", safety)
	}
	fmt.Fprintf(o.out, "The revert started a new snapshot branch. When the app runs again and the data is\n"+
		"confirmed, delete the old branch with: lh-snap-revert cleanup --pvc %s\n", o.pvc)
	fmt.Fprintln(o.out, "Ready to activate the app.")
	return nil
}

func release(ctx context.Context, a api, p *plan) error {
	if err := callAPI(ctx, func(c context.Context) error {
		return a.HoldRecurringJobs(c, p.volume, p.holdKeys, false)
	}); err != nil {
		return fmt.Errorf("restore recurring jobs: %w", err)
	}
	return nil
}

func detach(ctx context.Context, a api, o *revertOpts, volume string) error {
	if err := callAPI(ctx, func(c context.Context) error {
		return a.PatchTicket(c, volume, ticketID, nil)
	}); err != nil {
		return fmt.Errorf("remove attachment ticket: %w", err)
	}
	return waitFor(ctx, o, "detach", func(c context.Context) (bool, string, error) {
		va, err := a.VolumeAttachment(c, volume)
		if err != nil {
			return false, "", err
		}
		ticketGone := va == nil || va.Spec.AttachmentTickets[ticketID] == nil
		vol, err := a.Volume(c, volume)
		if err != nil {
			return false, "", err
		}
		return ticketGone && vol.Status.State == lh.VolumeStateDetached,
			fmt.Sprintf("state=%s ticketRemoved=%t", vol.Status.State, ticketGone), nil
	})
}

// idleCond reports a detached volume with no attachment tickets.
func idleCond(a api, volume string) func(context.Context) (bool, string, error) {
	return func(c context.Context) (bool, string, error) {
		va, err := a.VolumeAttachment(c, volume)
		if err != nil {
			return false, "", err
		}
		var ids []string
		if va != nil {
			for id := range va.Spec.AttachmentTickets {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		vol, err := a.Volume(c, volume)
		if err != nil {
			return false, "", err
		}
		return len(ids) == 0 && vol.Status.State == lh.VolumeStateDetached,
			fmt.Sprintf("state=%s tickets=[%s]", vol.Status.State, strings.Join(ids, " ")), nil
	}
}

func attachedCond(a api, p *plan) func(context.Context) (bool, string, error) {
	return func(c context.Context) (bool, string, error) {
		va, err := a.VolumeAttachment(c, p.volume)
		if err != nil {
			return false, "", err
		}
		satisfied, why := false, ""
		if va != nil {
			if s := va.Status.AttachmentTicketStatuses[ticketID]; s != nil {
				satisfied = s.Satisfied
				for _, cond := range s.Conditions {
					if cond.Message != "" {
						why = " (" + cond.Message + ")"
					}
				}
			}
		}
		vol, err := a.Volume(c, p.volume)
		if err != nil {
			return false, "", err
		}
		st := vol.Status
		done := satisfied && st.State == lh.VolumeStateAttached && st.FrontendDisabled && st.CurrentNodeID == p.node
		return done, fmt.Sprintf("state=%s node=%s frontendDisabled=%t ticketSatisfied=%t%s",
			st.State, st.CurrentNodeID, st.FrontendDisabled, satisfied, why), nil
	}
}

func snapshotReadyCond(a api, volume, name string) func(context.Context) (bool, string, error) {
	return func(c context.Context) (bool, string, error) {
		snaps, err := a.Snapshots(c, volume)
		if err != nil {
			return false, "", err
		}
		for _, s := range snaps {
			if s.Name != name {
				continue
			}
			// Longhorn retries and clears Status.Error, e.g. while the
			// engine is still starting, so an error is not final.
			status := fmt.Sprintf("readyToUse=%t", s.Status.ReadyToUse)
			if s.Status.Error != "" {
				status += " (" + s.Status.Error + ")"
			}
			return s.Status.ReadyToUse, status, nil
		}
		return false, "not created yet", nil
	}
}

func verifyPVC(ctx context.Context, a api, o *revertOpts, p *plan) error {
	var pvc *corev1.PersistentVolumeClaim
	if err := callAPI(ctx, func(c context.Context) error {
		var err error
		pvc, err = a.PVC(c, o.namespace, o.pvc)
		return err
	}); err != nil {
		return fmt.Errorf("re-read PVC: %w", err)
	}
	if string(pvc.UID) != p.pvcUID || pvc.Spec.VolumeName != p.pv || pvc.Status.Phase != corev1.ClaimBound {
		return fmt.Errorf("PVC changed: uid=%s (want %s) pv=%s (want %s) phase=%s",
			pvc.UID, p.pvcUID, pvc.Spec.VolumeName, p.pv, pvc.Status.Phase)
	}
	fmt.Fprintf(o.out, "    PVC %s unchanged: UID %s, PV %s, Bound\n", o.pvc, p.pvcUID, p.pv)
	return nil
}

// waitFor polls cond until it reports done, the timeout passes, or ctx is
// cancelled. API errors are retried.
func waitFor(ctx context.Context, o *revertOpts, what string,
	cond func(context.Context) (bool, string, error)) error {
	deadline := time.Now().Add(o.timeout)
	last := ""
	for {
		var done bool
		var status string
		err := callAPI(ctx, func(c context.Context) error {
			var err error
			done, status, err = cond(c)
			return err
		})
		if err != nil {
			status = "API error: " + err.Error()
		}
		if done {
			return nil
		}
		if status != last {
			fmt.Fprintf(o.out, "    %s: %s\n", what, status)
			last = status
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for %s (last: %s)", o.timeout, what, status)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for %s: %w", what, ctx.Err())
		case <-time.After(o.poll):
		}
	}
}

// callAPI bounds one round of API calls so a hung request cannot stall the
// tool past its timeouts.
func callAPI(ctx context.Context, f func(context.Context) error) error {
	c, cancel := context.WithTimeout(ctx, apiCallTimeout)
	defer cancel()
	return f(c)
}

func step(o *revertOpts, n int, format string, args ...interface{}) {
	fmt.Fprintf(o.out, "==> Step %d: %s\n", n, fmt.Sprintf(format, args...))
}

func manualDetachCmd(volume string) string {
	return fmt.Sprintf(`eve exec kube kubectl -n %s patch volumeattachments.longhorn.io %s --type merge -p '{"spec":{"attachmentTickets":{"%s":null}}}'`,
		longhornNamespace, volume, ticketID)
}

func deleteSnapshotCmd(name string) string {
	return fmt.Sprintf("eve exec kube kubectl -n %s delete snapshots.longhorn.io %s --wait=false",
		longhornNamespace, name)
}

// attachedError explains what keeps the volume attached.
func attachedError(ctx context.Context, a api, pvc string, vol *lh.Volume, va *lh.VolumeAttachment) error {
	var b strings.Builder
	fmt.Fprintf(&b, "volume %s is %q", vol.Name, vol.Status.State)
	if vol.Status.CurrentNodeID != "" {
		fmt.Fprintf(&b, " on %s", vol.Status.CurrentNodeID)
	}
	if va == nil || len(va.Spec.AttachmentTickets) == 0 {
		b.WriteString(" with no attachment tickets. Longhorn is detaching it; try again shortly")
		return errors.New(b.String())
	}
	if vol.Status.State == lh.VolumeStateDetached {
		b.WriteString(" but still has attachment tickets:")
	} else {
		b.WriteString(", expected detached. Held by:")
	}
	ids := make([]string, 0, len(va.Spec.AttachmentTickets))
	for id := range va.Spec.AttachmentTickets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var tree *snapTree
	if snaps, err := a.Snapshots(ctx, vol.Name); err == nil {
		tree = newSnapTree(snaps)
	}
	for _, id := range ids {
		t := va.Spec.AttachmentTickets[id]
		if t == nil {
			t = &lh.AttachmentTicket{}
		}
		fmt.Fprintf(&b, "\n  %s (%s on %s)", id, t.Type, t.NodeID)
		if hint := ticketHint(id, t, tree, pvc, vol.Name); hint != "" {
			b.WriteString("\n    " + hint)
		}
	}
	return errors.New(b.String())
}

func ticketHint(id string, t *lh.AttachmentTicket, tree *snapTree, pvc, volume string) string {
	if id == ticketID {
		return "A previous run left its ticket behind. Remove it with:\n      " + manualDetachCmd(volume)
	}
	switch t.Type {
	case lh.AttacherTypeCSIAttacher:
		return "The app is still running, or Kubernetes is still detaching the volume."
	case lh.AttacherTypeSnapshotController:
		name := strings.TrimPrefix(id, string(lh.AttacherTypeSnapshotController)+"-")
		if tree == nil || tree.byName[name] == nil {
			return "Longhorn is creating or deleting snapshot " + name + "."
		}
		if s := tree.byName[name]; purgeBlocked(s) {
			return fmt.Sprintf("Snapshot %s is being deleted but has %d children. Longhorn cannot purge it "+
				"and keeps the volume attached until all but one branch below it are deleted. "+
				"See the tree with: lh-snap-revert list --pvc %s", name, len(s.Status.Children), pvc)
		}
		return "Longhorn is creating or deleting snapshot " + name + "."
	}
	return ""
}
