// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSanitizeRef(t *testing.T) {
	cases := map[string]string{
		"quay.io/kubevirt/virt-operator:v1.7.3":        "quay.io_kubevirt_virt-operator_v1.7.3",
		"docker.io/longhornio/longhorn-manager:v1.9.1": "docker.io_longhornio_longhorn-manager_v1.9.1",
	}
	for in, want := range cases {
		if got := sanitizeRef(in); got != want {
			t.Errorf("sanitizeRef(%q)=%q want %q", in, got, want)
		}
	}
}

func TestLoadRefMapMissingFileIsEmpty(t *testing.T) {
	m, err := loadRefMap(filepath.Join(t.TempDir(), "nope.list"))
	if err != nil {
		t.Fatalf("want nil err for missing catalog, got %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("want empty map, got %d entries", len(m))
	}
}

func TestLoadRefMap(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "upstream-images.list")
	// The shipped list pins each ref by digest. The digest says what the
	// build pulled; the name kubelet's pod specs use is the tag, so it is
	// the tag that has to come back out of the map.
	if err := os.WriteFile(list, []byte(
		"# generated\n"+
			"quay.io/kubevirt/virt-operator:v1.7.3@sha256:176c2c36cd1def7794f52eb08e05010ebf17885debb109a72b4d91bd8da06bea\n"+
			"\ndocker.io/longhornio/longhorn-ui:v1.9.1@sha256:7e235c4781e62aff644882ed50fbaebc06696d08fcf6b5d5174d71a0a67a92b0\n"),
		0644); err != nil {
		t.Fatal(err)
	}
	m, err := loadRefMap(list)
	if err != nil {
		t.Fatal(err)
	}
	if m["quay.io_kubevirt_virt-operator_v1.7.3"] != "quay.io/kubevirt/virt-operator:v1.7.3" {
		t.Errorf("bad map: %+v", m)
	}
	if len(m) != 2 {
		t.Errorf("want 2 entries, got %d: %+v", len(m), m)
	}
}
