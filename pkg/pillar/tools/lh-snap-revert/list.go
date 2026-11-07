// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	lh "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	corev1 "k8s.io/api/core/v1"
)

const volumeHead = "volume-head"

// listPVCs prints the namespace's PVCs with their Longhorn volume and users.
func listPVCs(ctx context.Context, a api, ns string, out io.Writer) error {
	pvcs, err := a.PVCs(ctx, ns)
	if err != nil {
		return fmt.Errorf("list PVCs in %s: %w", ns, err)
	}
	sort.Slice(pvcs, func(i, j int) bool { return pvcs[i].Name < pvcs[j].Name })
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PVC\tVOLUME\tSIZE\tSTATE\tROBUSTNESS\tJOBS\tUSED BY")
	for _, pvc := range pvcs {
		volName, state, robustness, jobs := "-", "-", "-", "-"
		if _, v, err := resolveVolume(ctx, a, ns, pvc.Name); err == nil {
			volName = v
			if vol, err := a.Volume(ctx, v); err == nil {
				state, robustness = string(vol.Status.State), string(vol.Status.Robustness)
				if len(heldLabels(vol)) > 0 {
					jobs = "held"
				}
			}
		}
		users, err := a.PVCUsers(ctx, ns, pvc.Name)
		usedBy := strings.Join(users, ",")
		switch {
		case err != nil:
			usedBy = "?"
		case usedBy == "":
			usedBy = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			pvc.Name, volName, pvcSize(pvc), state, robustness, jobs, usedBy)
	}
	return tw.Flush()
}

func pvcSize(pvc corev1.PersistentVolumeClaim) string {
	if q, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok {
		return q.String()
	}
	return "-"
}

// listSnapshots prints the snapshot tree of the volume behind a PVC.
func listSnapshots(ctx context.Context, a api, ns, pvcName string, out io.Writer) error {
	_, volName, err := resolveVolume(ctx, a, ns, pvcName)
	if err != nil {
		return err
	}
	snaps, err := a.Snapshots(ctx, volName)
	if err != nil {
		return fmt.Errorf("list snapshots of %s: %w", volName, err)
	}
	fmt.Fprintf(out, "Snapshots of volume %s (PVC %s/%s), oldest first. %s is the current data.\n",
		volName, ns, pvcName, volumeHead)
	if vol, err := a.Volume(ctx, volName); err == nil && vol.Status.State != lh.VolumeStateAttached {
		fmt.Fprintln(out, "The volume is not attached. Longhorn updates the tree only while it is attached.")
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tCREATED\tSIZE\tORIGIN\tSTATE")
	t := newSnapTree(snaps)
	for _, r := range t.roots {
		t.print(tw, r, "", "")
	}
	return tw.Flush()
}

// formatSize prints bytes in the largest binary unit that keeps a value of
// at least 1, so that a small snapshot does not show as 0.
func formatSize(b int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	f, i := float64(b), 0
	for ; f >= 1024 && i < len(units)-1; i++ {
		f /= 1024
	}
	if i == 0 {
		return fmt.Sprintf("%d B", b)
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

func snapshotOrigin(s *lh.Snapshot) string {
	switch {
	case s.Name == volumeHead:
		return "-"
	case s.Status.Labels["RecurringJob"] != "":
		return "recurring:" + s.Status.Labels["RecurringJob"]
	case s.Status.UserCreated:
		return "user"
	}
	return "system"
}

func snapshotState(s *lh.Snapshot) string {
	if s.Name == volumeHead {
		return "current data"
	}
	var st []string
	switch {
	case s.DeletionTimestamp != nil:
		st = append(st, "deleting")
	case s.Status.MarkRemoved:
		st = append(st, "removed")
	case creating(s):
		st = append(st, "creating")
	case s.Status.ReadyToUse:
		st = append(st, "ready")
	default:
		st = append(st, "not ready")
	}
	if purgeBlocked(s) {
		st = append(st, fmt.Sprintf("%d children, cannot be purged", len(s.Status.Children)))
	}
	if s.Status.Error != "" {
		st = append(st, "error: "+s.Status.Error)
	}
	return strings.Join(st, ", ")
}

// creating reports a snapshot CR that the engine has not reported yet. It
// has no parent until then. Longhorn uses the same test.
func creating(s *lh.Snapshot) bool {
	return s.Name != volumeHead && s.Status.CreationTime == ""
}

// purgeBlocked reports a snapshot that is to be removed but has more than
// one child. The Longhorn engine cannot purge it, and while it is being
// deleted Longhorn can keep the volume attached.
func purgeBlocked(s *lh.Snapshot) bool {
	return (s.DeletionTimestamp != nil || s.Status.MarkRemoved) && len(s.Status.Children) > 1
}

// snapTree is the snapshot tree built from each Snapshot CR's parent.
// Longhorn has no CR for volume-head, so the tree adds it under the
// snapshot that lists it as a child.
type snapTree struct {
	byName map[string]*lh.Snapshot
	kids   map[string][]string
	roots  []string
	live   map[string]bool // volume-head and its ancestors; nil if unknown
}

func newSnapTree(snaps []lh.Snapshot) *snapTree {
	t := &snapTree{byName: map[string]*lh.Snapshot{}, kids: map[string][]string{}}
	for i := range snaps {
		if snaps[i].Name != volumeHead {
			t.byName[snaps[i].Name] = &snaps[i]
		}
	}
	headParent := ""
	for _, s := range t.byName {
		if s.Status.Children[volumeHead] && (headParent == "" ||
			s.Status.CreationTime > t.byName[headParent].Status.CreationTime) {
			headParent = s.Name
		}
	}
	if headParent != "" {
		t.byName[volumeHead] = &lh.Snapshot{}
		t.byName[volumeHead].Name = volumeHead
		t.byName[volumeHead].Status.Parent = headParent
	}
	for name, s := range t.byName {
		if p := s.Status.Parent; t.byName[p] != nil && p != name {
			t.kids[p] = append(t.kids[p], name)
		} else {
			t.roots = append(t.roots, name)
		}
	}
	for _, k := range t.kids {
		t.sort(k)
	}
	t.sort(t.roots)
	if headParent != "" {
		t.live = map[string]bool{}
		for n := volumeHead; t.byName[n] != nil && !t.live[n]; n = t.byName[n].Status.Parent {
			t.live[n] = true
		}
	}
	return t
}

// oldBranch returns the snapshots that are not on the current data's chain,
// not being created and not already being deleted.
func (t *snapTree) oldBranch() []string {
	var out []string
	for name, s := range t.byName {
		if !t.live[name] && !creating(s) && s.DeletionTimestamp == nil {
			out = append(out, name)
		}
	}
	t.sort(out)
	return out
}

// sort orders by creation time; volume-head has none and goes last.
func (t *snapTree) sort(names []string) {
	key := func(n string) string {
		if n == volumeHead {
			return "~"
		}
		return t.byName[n].Status.CreationTime + n
	}
	sort.Slice(names, func(i, j int) bool { return key(names[i]) < key(names[j]) })
}

// print writes a chain of single children at one indent level and indents
// only where the tree branches.
func (t *snapTree) print(w io.Writer, name, prefix, cont string) {
	t.printSeen(w, name, prefix, cont, map[string]bool{})
}

func (t *snapTree) printSeen(w io.Writer, name, prefix, cont string, seen map[string]bool) {
	for !seen[name] {
		seen[name] = true
		s := t.byName[name]
		size := "-"
		if name != volumeHead {
			size = formatSize(s.Status.Size)
		}
		state := snapshotState(s)
		if t.live != nil && !t.live[name] && !creating(s) {
			state = "old branch, " + state
		}
		fmt.Fprintf(w, "%s%s\t%s\t%s\t%s\t%s\n", prefix, name, s.Status.CreationTime, size,
			snapshotOrigin(s), state)
		kids := t.kids[name]
		if len(kids) != 1 {
			for i, c := range kids {
				if i == len(kids)-1 {
					t.printSeen(w, c, cont+"`- ", cont+"   ", seen)
				} else {
					t.printSeen(w, c, cont+"|- ", cont+"|  ", seen)
				}
			}
			return
		}
		name, prefix = kids[0], cont
	}
}
