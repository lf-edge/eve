// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// newlogRecord renders msg the way newlogd stores a pillar record.
func newlogRecord(t *testing.T, seconds int64, msg string) string {
	inner, err := json.Marshal(map[string]string{"msg": msg, "source": "volumemgr"})
	if err != nil {
		t.Fatal(err)
	}
	outer, err := json.Marshal(map[string]interface{}{
		"content":   string(inner),
		"source":    "volumemgr",
		"timestamp": map[string]int64{"seconds": seconds, "nanos": 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(outer)
}

func TestPVCUploadReport(t *testing.T) {
	const data = "2f9619e9-ebeb-4d0f-98aa-d0626a5c6728-pvc-0"
	const image = "e6119b69-6650-4ec9-a272-62346b990b76-pvc-0"
	started := func(pvc string) string {
		return "virtctl args [image-upload -n eve-kube-app pvc " + pvc + " --no-create]"
	}
	done := func(pvc string) string {
		return fmt.Sprintf("RolloutDiskToPVC pvc:%s image upload completed on try:1 "+
			"after virtctl-image-upload:56.0 seconds, cdi-upload-annotation-wait:5.0 seconds, "+
			"total-elapsed-time:61.0 seconds", pvc)
	}
	populate := func(pvc string) string { return "Populate called for PVC " + pvc }

	tests := []struct {
		name string
		msgs []string
		want string
	}{
		{
			// The unfixed image: the data volume's upload never completes,
			// the device reboots, and Populate adopts the partial PVC.
			name: "reboot mid-upload, partial PVC adopted",
			msgs: []string{
				populate(data), populate(image),
				started(data), started(image), done(image),
				populate(data), populate(image),
			},
			want: "unfinished-at-populate=1 recovered=0 done=1 populate=4 started=2",
		},
		{
			name: "reboot mid-upload, upload re-driven",
			msgs: []string{
				started(data),
				populate(data),
				"Populate: PVC " + data + " upload state incomplete",
				"CreateVolume: PVC " + data + " exists but upload not complete (upload state incomplete), re-driving upload",
				started(data), done(data),
			},
			want: "unfinished-at-populate=1 recovered=1 done=1 populate=1 " +
				"populate-incomplete=1 redrive=1 started=2",
		},
		{
			name: "no reboot during the upload",
			msgs: []string{
				started(data), done(data),
				populate(data),
				"Populate: PVC " + data + " upload state complete",
				"Populate: PVC " + data + " upload state unknown, treating as not-yet-created: x",
			},
			want: "unfinished-at-populate=0 recovered=0 done=1 populate=1 " +
				"populate-complete=1 populate-unknown=1 started=1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var lines []string
			for i, m := range tc.msgs {
				lines = append(lines, newlogRecord(t, int64(1000+i), m))
			}
			// Records arrive in file order, not time order.
			lines[0], lines[len(lines)-1] = lines[len(lines)-1], lines[0]
			lines = append(lines, "not json", "")
			got := summarizePVCUploadEvents(parsePVCUploadEvents(strings.Join(lines, "\n"))).String()
			if got != tc.want {
				t.Errorf("report:\n got %s\nwant %s", got, tc.want)
			}
		})
	}
}
