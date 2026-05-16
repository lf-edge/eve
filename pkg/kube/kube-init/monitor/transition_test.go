// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// TestParseReadyCount covers the kubectl-output parser used to
// gate the cluster-join state machine. Non-trivial cases:
//   - "Ready,SchedulingDisabled" must count (cordoned tie-breaker
//     still satisfies the join quorum).
//   - "NotReady" must not count.
//   - Rows with fewer than 2 fields must be ignored without panic.
//   - Empty / blank output produces 0 (no rows).
func TestParseReadyCount(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{
			name: "two Ready nodes",
			in:   "n1 Ready master 5m v1\nn2 Ready worker 5m v1",
			want: 2,
		},
		{
			name: "Ready,SchedulingDisabled counts",
			in:   "n1 Ready master 5m v1\nn2 Ready,SchedulingDisabled tie 5m v1",
			want: 2,
		},
		{
			name: "NotReady does not count",
			in:   "n1 Ready master 5m v1\nn2 NotReady worker 5m v1",
			want: 1,
		},
		{
			name: "row with one field is skipped (no panic)",
			in:   "shortrow\nn1 Ready master 5m v1",
			want: 1,
		},
		{
			name: "empty input → 0",
			in:   "",
			want: 0,
		},
		{
			name: "whitespace-only input → 0",
			in:   "  \n  ",
			want: 0,
		},
		{
			name: "Ready prefix but different status (e.g. 'ReadyForJoin') counts as Ready",
			in:   "n1 ReadyForJoin master 5m v1",
			want: 1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseReadyCount(c.in); got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

// TestParseTransitionMarker covers the timestamp+counter parse +
// sanity-check used by CheckClusterTransitionDone. The
// validation we own:
//   - Two whitespace-separated fields required.
//   - Timestamp must be > 0.
//   - Timestamp must not be >60s in the future.
//   - Reboot count must parse as an int.
func TestParseTransitionMarker(t *testing.T) {
	now := time.Now().Unix()

	cases := []struct {
		name    string
		content string
		wantTS  int64
		wantCnt int
		wantErr bool
	}{
		{
			name:    "valid recent",
			content: fmt.Sprintf("%d 2", now-30),
			wantTS:  now - 30,
			wantCnt: 2,
		},
		{
			name:    "single field rejected",
			content: fmt.Sprintf("%d", now),
			wantErr: true,
		},
		{
			name:    "empty file rejected",
			content: "",
			wantErr: true,
		},
		{
			name:    "non-numeric timestamp rejected",
			content: "notanumber 1",
			wantErr: true,
		},
		{
			name:    "non-numeric count rejected",
			content: fmt.Sprintf("%d bogus", now),
			wantErr: true,
		},
		{
			name:    "zero timestamp rejected",
			content: "0 1",
			wantErr: true,
		},
		{
			name:    "negative timestamp rejected",
			content: "-5 1",
			wantErr: true,
		},
		{
			name:    "more than 60s in the future rejected",
			content: fmt.Sprintf("%d 1", now+120),
			wantErr: true,
		},
		{
			name:    "60s tolerance accepted",
			content: fmt.Sprintf("%d 1", now+30),
			wantTS:  now + 30,
			wantCnt: 1,
		},
		{
			name:    "trailing whitespace tolerated",
			content: fmt.Sprintf("  %d   3  ", now-10),
			wantTS:  now - 10,
			wantCnt: 3,
		},
		{
			name:    "extra fields tolerated (first two win)",
			content: fmt.Sprintf("%d 1 extra-junk", now-5),
			wantTS:  now - 5,
			wantCnt: 1,
		},
	}

	dir := t.TempDir()
	tmp := dir + "/marker"
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(tmp, []byte(c.content), 0644); err != nil {
				t.Fatalf("seed: %v", err)
			}
			ts, cnt, err := parseTransitionMarker(tmp)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
			if c.wantErr {
				return
			}
			if ts != c.wantTS {
				t.Errorf("ts = %d, want %d", ts, c.wantTS)
			}
			if cnt != c.wantCnt {
				t.Errorf("cnt = %d, want %d", cnt, c.wantCnt)
			}
		})
	}
}
