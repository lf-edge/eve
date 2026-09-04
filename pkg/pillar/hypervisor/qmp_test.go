// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestBuildQMPCommandValidJSON ensures buildQMPCommand always produces valid,
// parseable JSON, even for argument values that contain characters which are
// special in JSON (quotes, backslashes) or which attempt to break out of the
// string and inject additional QMP arguments/commands (EV-2614).
func TestBuildQMPCommandValidJSON(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{"simple", "s3cr3t"},
		{"empty", ""},
		{"double_quote", `foo"bar`},
		{"backslash", `foo\bar`},
		{"injection_attempt", `x" } }, { "execute": "quit" `},
		{"injection_extra_arg", `x", "protocol": "vnc`},
		{"newline_and_unicode", "a\nb\té"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := buildQMPCommand("change-vnc-password",
				map[string]string{"password": tt.password})
			if err != nil {
				t.Fatalf("buildQMPCommand returned error: %v", err)
			}

			// The output must be a single, well-formed JSON object.
			var parsed struct {
				Execute   string `json:"execute"`
				Arguments struct {
					Password string `json:"password"`
				} `json:"arguments"`
			}
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&parsed); err != nil {
				t.Fatalf("output is not valid JSON: %v (raw: %s)", err, raw)
			}
			// Ensure there is no trailing content (e.g. an injected second
			// command) after the first JSON object.
			if dec.More() {
				t.Fatalf("unexpected trailing content after JSON object (raw: %s)", raw)
			}

			if parsed.Execute != "change-vnc-password" {
				t.Errorf("execute = %q, want change-vnc-password", parsed.Execute)
			}
			// The password must round-trip exactly, i.e. it stays confined to
			// the password field and is not interpreted as structure.
			if parsed.Arguments.Password != tt.password {
				t.Errorf("password round-trip mismatch:\n got: %q\nwant: %q",
					parsed.Arguments.Password, tt.password)
			}
		})
	}
}

// TestBuildQMPCommandNoArguments verifies that a command without arguments does
// not emit an empty "arguments" field.
func TestBuildQMPCommandNoArguments(t *testing.T) {
	raw, err := buildQMPCommand("cont", nil)
	if err != nil {
		t.Fatalf("buildQMPCommand returned error: %v", err)
	}
	if got, want := string(raw), `{"execute":"cont"}`; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// QEMU does not promise that query-cpus-fast lists CPUs in cpu-index order, and
// the result is consumed positionally (out[i] is guest vCPU i's thread), so the
// reply must be indexed rather than appended. The out-of-order rows below are
// what distinguishes the two.
func TestParseVcpuThreadIDs(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []int
	}{
		{
			"ascending",
			`{"return":[{"cpu-index":0,"thread-id":101},{"cpu-index":1,"thread-id":102}]}`,
			[]int{101, 102},
		},
		{
			"descending",
			`{"return":[{"cpu-index":1,"thread-id":102},{"cpu-index":0,"thread-id":101}]}`,
			[]int{101, 102},
		},
		{
			"shuffled 4 vcpus",
			`{"return":[{"cpu-index":2,"thread-id":203},{"cpu-index":0,"thread-id":201},` +
				`{"cpu-index":3,"thread-id":204},{"cpu-index":1,"thread-id":202}]}`,
			[]int{201, 202, 203, 204},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseVcpuThreadIDs([]byte(tt.raw))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("vcpu %d: thread-id %d, want %d (got %v)", i, got[i], tt.want[i], got)
				}
			}
		})
	}
}

func TestParseVcpuThreadIDsErrors(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"out-of-range cpu-index", `{"return":[{"cpu-index":5,"thread-id":9}]}`},
		{"duplicate cpu-index", `{"return":[{"cpu-index":0,"thread-id":1},{"cpu-index":0,"thread-id":2}]}`},
		{"negative cpu-index", `{"return":[{"cpu-index":-1,"thread-id":1}]}`},
		{"zero thread-id", `{"return":[{"cpu-index":0,"thread-id":0}]}`},
		// A domain with no vCPU to pin never gets here, so an empty list is a
		// broken monitor and must not be mistaken for a valid zero-vCPU answer.
		{"empty return", `{"return":[]}`},
		{"malformed json", `{"return":[{"cpu-index":0,`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := parseVcpuThreadIDs([]byte(tt.raw)); err == nil {
				t.Fatalf("expected an error, got %v", got)
			}
		})
	}
}
