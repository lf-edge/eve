// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/onsi/gomega"
)

func TestAppErrors(t *testing.T) {
	errTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lifecycle := types.ErrorDescription{Error: "boot failed", ErrorTime: errTime,
		ErrorSeverity: types.ErrorSeverityError}
	runtime := types.ErrorDescription{Error: "cloud-init failed", ErrorTime: errTime,
		ErrorSeverity: types.ErrorSeverityWarning}

	tests := []struct {
		name      string
		lifecycle types.ErrorDescription
		runtime   types.ErrorDescription
		want      []string
	}{
		{name: "no errors"},
		{name: "runtime only", runtime: runtime, want: []string{"cloud-init failed"}},
		{name: "lifecycle and runtime", lifecycle: lifecycle, runtime: runtime,
			want: []string{"boot failed", "cloud-init failed"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			status := &types.AppInstanceStatus{RuntimeErr: tt.runtime}
			status.ErrorDescription = tt.lifecycle
			errs := appErrors(status)
			g.Expect(errs).To(gomega.HaveLen(len(tt.want)))
			for i, e := range errs {
				g.Expect(e).ToNot(gomega.BeNil())
				g.Expect(e.GetDescription()).To(gomega.Equal(tt.want[i]))
			}
			if tt.runtime.Error != "" {
				g.Expect(errs[len(errs)-1].GetSeverity().String()).To(
					gomega.Equal("SEVERITY_WARNING"))
			}
		})
	}
}

// The controller learns about a snapshot only from this list, so one that
// could not be created or deleted has to be on it with its error.
func TestSnapshotInfosIncludeFailures(t *testing.T) {
	g := gomega.NewWithT(t)
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snap := func(id string) types.SnapshotInstanceStatus {
		return types.SnapshotInstanceStatus{Snapshot: types.SnapshotDesc{SnapshotID: id}}
	}
	available := snap("available")
	available.TimeCreated = created
	failed := snap("failed")
	failed.Error = types.ErrorDescription{Error: "qemu-img failed", ErrorTime: created}

	infos := snapshotInfos(types.SnapshottingStatus{
		Snapshots: []types.SnapshotInstanceStatus{available, failed},
	})

	g.Expect(infos).To(gomega.HaveLen(2))
	g.Expect(infos[0].Id).To(gomega.Equal("available"))
	g.Expect(infos[0].CreateTime.AsTime()).To(gomega.Equal(created))
	g.Expect(infos[0].SnapErr).To(gomega.BeNil())
	g.Expect(infos[1].Id).To(gomega.Equal("failed"))
	g.Expect(infos[1].CreateTime).To(gomega.BeNil())
	g.Expect(infos[1].SnapErr.GetDescription()).To(gomega.Equal("qemu-img failed"))
}
