// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package kubeapi

import (
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

/*
func TestRegistration(t *testing.T) {
	registrationYamlPath := "/registration.yaml"
	httpServerPort := "127.0.0.1:8080"

	// Generate a tmpfile path
	tmpdir, err := os.MkdirTemp("", "testregistration")
	if err != nil {
		t.Fatalf("os.MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	// start a basic local http server serving a yaml
	httpMux := http.NewServeMux()
	httpMux.HandleFunc(registrationYamlPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(basicYaml))
	})
	httpSrv := http.Server{
		Addr:    httpServerPort,
		Handler: httpMux,
	}

	go func() {
		httpSrv.ListenAndServe()
	}()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = RegistrationAdd(tmpdir, "http://"+httpServerPort+registrationYamlPath)
	httpSrv.Shutdown(shutdownCtx)
	if err != nil {
		t.Fatalf("Registration add failure: %v", err)
	}
}
*/

func TestRegistration(t *testing.T) {
	// Generate a tmpfile path
	tmpdir, err := os.MkdirTemp("", "testregistration")
	if err != nil {
		t.Fatalf("os.MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	err = RegistrationAdd(tmpdir, []byte(basicYaml))
	if err != nil {
		t.Fatalf("Registration add failure: %v", err)
	}
}
