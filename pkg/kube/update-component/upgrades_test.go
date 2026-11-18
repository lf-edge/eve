// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestFetchManifest(t *testing.T) {
	const body = "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: cdi\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ok.yaml" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	file, err := fetchManifest(srv.URL + "/ok.yaml")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	defer func() { _ = os.Remove(file) }()
	got, err := os.ReadFile(file)
	if err != nil || string(got) != body {
		t.Fatalf("fetched %q, %v; want %q", got, err, body)
	}

	if file, err := fetchManifest(srv.URL + "/missing.yaml"); err == nil {
		_ = os.Remove(file)
		t.Fatal("fetch of a missing manifest succeeded")
	}
}

// fakeComponent is ready at readyAt only; as a resumer it reports applied
// for appliedAt.
type fakeComponent struct {
	readyAt, appliedAt string
	appliedErr         error
}

func (f fakeComponent) GetVersion() (string, error)           { return "", nil }
func (f fakeComponent) UpgradeSupported(string, string) error { return nil }
func (f fakeComponent) Uptime(string) (time.Time, error)      { return time.Time{}, nil }
func (f fakeComponent) UpgradeStart(string) error             { return nil }

func (f fakeComponent) Ready(version string) error {
	if version != f.readyAt {
		return errors.New("not ready")
	}
	return nil
}

func (f fakeComponent) Applied(version string) (bool, error) {
	return version == f.appliedAt, f.appliedErr
}

// plainComponent has no Applied, so it can never resume.
type plainComponent struct{ fakeComponent }

func (p plainComponent) Applied() {}

func TestUpgradeReady(t *testing.T) {
	tests := []struct {
		name       string
		comp       KubeComponent
		wantResume bool
		wantErr    bool
	}{
		{"ready at current", fakeComponent{readyAt: "v1"}, false, false},
		{"not ready, nothing applied", fakeComponent{}, false, true},
		{"not ready, target applied", fakeComponent{appliedAt: "v2"}, true, false},
		{"not ready, other version applied", fakeComponent{appliedAt: "v3"}, false, true},
		{"not ready, applied unknown", fakeComponent{appliedAt: "v2",
			appliedErr: errors.New("api")}, false, true},
		{"not ready, no resumer", plainComponent{fakeComponent{appliedAt: "v2"}}, false, true},
	}
	for _, tc := range tests {
		resume, err := upgradeReady(tc.comp, "v1", "v2")
		if resume != tc.wantResume || (err != nil) != tc.wantErr {
			t.Errorf("%s: got resume=%v err=%v, want resume=%v err=%v",
				tc.name, resume, err, tc.wantResume, tc.wantErr)
		}
	}
}
