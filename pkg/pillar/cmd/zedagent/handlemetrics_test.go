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
