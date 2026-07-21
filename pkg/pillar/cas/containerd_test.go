// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cas

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveUserGroup guards the EVE-k volume-preparation path that maps an
// OCI image Config.User string to a numeric uid/gid pair.
func TestResolveUserGroup(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	passwd := "root:x:0:0:root:/root:/bin/bash\nzcli:x:1000:1000:Linux User:/home/zcli:/bin/bash\n"
	group := "root:x:0:\nstaff:x:50:\nzcli:x:1000:\n"
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "passwd"), []byte(passwd), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "group"), []byte(group), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		userstr  string
		uid, gid uint32
		wantErr  bool
	}{
		{userstr: "", uid: 0, gid: 0},
		{userstr: "zcli", uid: 1000, gid: 1000},  // username resolved from /etc/passwd
		{userstr: "1000", uid: 1000, gid: 1000},  // numeric uid; gid from passwd
		{userstr: "1234", uid: 1234, gid: 0},     // uid absent from passwd; gid falls back to 0
		{userstr: "1000:50", uid: 1000, gid: 50}, // numeric group overrides
		{userstr: "zcli:staff", uid: 1000, gid: 50},
		{userstr: "1000:staff", uid: 1000, gid: 50},
		{userstr: "nobody", wantErr: true},
		{userstr: "zcli:nogroup", wantErr: true},
		{userstr: "2147483648", wantErr: true},      // uid > math.MaxInt32
		{userstr: "1000:2147483648", wantErr: true}, // gid > math.MaxInt32
	}
	for _, tt := range tests {
		uid, gid, err := resolveUserGroup(rootfs, tt.userstr)
		if tt.wantErr {
			if err == nil {
				t.Errorf("resolveUserGroup(%q): expected error, got uid=%d gid=%d", tt.userstr, uid, gid)
			}
			continue
		}
		if err != nil {
			t.Errorf("resolveUserGroup(%q): unexpected error: %v", tt.userstr, err)
			continue
		}
		if uid != tt.uid || gid != tt.gid {
			t.Errorf("resolveUserGroup(%q) = %d/%d, want %d/%d", tt.userstr, uid, gid, tt.uid, tt.gid)
		}
	}
}
