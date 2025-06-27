// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func listenHTTP() (*http.Request, error) {
	var s *http.Server
	sm := http.NewServeMux()
	var req *http.Request
	var bodyCloseErr error
	var shutdownErr error

	sm.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		req = r

		http.Error(w, "Bye", http.StatusOK)

		bodyCloseErr = r.Body.Close()
		shutdownErr = s.Shutdown(context.Background())

	})

	s = &http.Server{
		Addr:    ":8080",
		Handler: sm,
	}

	err := s.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}

	if bodyCloseErr != nil {
		return nil, bodyCloseErr
	}
	if shutdownErr != nil {
		return nil, shutdownErr
	}

	return req, nil
}

// TestCollectInfoUpload creates an http server and calls collect-info.sh to upload the tarball to it
func TestCollectInfoUpload(t *testing.T) {
	var cmd *exec.Cmd
	reqChan := make(chan *http.Request)
	go func() {
		req, err := listenHTTP()
		if err != nil {
			t.Logf("error from http server: %+v", err)
		}
		err = cmd.Process.Kill()
		if err != nil {
			t.Logf("could not kill process: %+v", err)
		}
		reqChan <- req
	}()

	for _, dir := range []string{"/proc/self", "/persist/status"} {
		err := os.MkdirAll(filepath.Join("/out", dir), 0700)
		if err != nil {
			t.Fatal(err)
		}
	}

	defer func() {
		for _, dir := range []string{"/proc/self", "/persist"} {
			err := os.RemoveAll(filepath.Join("/out", dir))
			if err != nil {
				t.Fatal(err)
			}
		}
	}()

	for _, fileContent := range []struct {
		file    string
		content string
	}{
		{
			file:    "/out/proc/self/cgroup",
			content: "/eve/services/debug",
		},
		{
			file:    "/out/persist/status/uuid",
			content: "123456",
		},
	} {

		err := os.WriteFile(fileContent.file, []byte(fileContent.content), 0600)
		if err != nil {
			t.Fatal(err)
		}
	}

	cmd = exec.Command("/usr/bin/collect-info.sh", "-u", "http://localhost:8080")
	cmd.Env = []string{"AUTHORIZATION=Bearer Vm0weGQxSXhiRmRXV0d4V1YwZDRWRmxyVm5kVmJGcHlWV3RLVUZWVU1Eaz0="}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Chroot: "/out",
	}
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	_ = cmd.Run()

	req := <-reqChan
	t.Logf("req: %+v", req)

	if req.Header["Authorization"][0] != "Bearer Vm0weGQxSXhiRmRXV0d4V1YwZDRWRmxyVm5kVmJGcHlWV3RLVUZWVU1Eaz0=" {
		t.Fatalf("authorization header wrong or not set - was %+v", req.Header["Authorization"])
	}

	if !strings.Contains(req.URL.Path, "123456") {
		t.Fatalf("http file path does not contain uuid; req: %+v", req)
	}
}
