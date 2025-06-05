// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package kubeapi

import (
	"bytes"
	"compress/gzip"
	"os"
	"testing"
)

const basicYaml string = `
apiVersion: v1
kind: ConfigMap
metadata:
  name: example-registration
data:
  server: 'controller1'`

func TestRegistration(t *testing.T) {
	// Generate a tmpfile path
	tmpdir, err := os.MkdirTemp("", "testregistration")
	if err != nil {
		t.Fatalf("os.MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	// Gzip the above yaml to simulate the decrypted form passed in eve-api
	var gzipBuf bytes.Buffer
	gz := gzip.NewWriter(&gzipBuf)
	_, err = gz.Write([]byte(basicYaml))
	if err != nil {
		t.Fatalf("unable to gzip yaml: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("unable to close gzip handle: %v", err)
	}

	err = RegistrationAdd(tmpdir, gzipBuf.Bytes())
	if err != nil {
		t.Fatalf("Registration add failure: %v", err)
	}
}
