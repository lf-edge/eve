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
	"sync"
	"syscall"
	"testing"
)

func listenHTTP() (*http.Request, error) {
	var serverShutdown sync.Mutex
	var s *http.Server
	sm := http.NewServeMux()
	var req *http.Request
	var bodyCloseErr error
	var shutdownErr error

	sm.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		req = r

		http.Error(w, "Bye", http.StatusOK)

		defer func() {
			bodyCloseErr = r.Body.Close()
			go func() {
				shutdownErr = s.Shutdown(context.Background())
				serverShutdown.Unlock()
			}()
		}()
	})

	s = &http.Server{
		Addr:    ":8080",
		Handler: sm,
	}

	serverShutdown.Lock()
	err := s.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}

	serverShutdown.Lock()
	if bodyCloseErr != nil {
		return nil, bodyCloseErr
	}
	if shutdownErr != nil {
		return nil, shutdownErr
	}

	return req, nil
}

func cleanup(t *testing.T) {
	for _, dir := range []string{"/proc/self", "/persist"} {
		err := os.RemoveAll(filepath.Join("/out", dir))
		if err != nil {
			t.Fatal(err)
		}
	}
}

func runCollectInfo(t *testing.T, uploadServer string, cmdEnv []string, httpListener func() (*http.Request, error)) *http.Request {
	var cmd *exec.Cmd
	reqChan := make(chan *http.Request)
	go func() {
		req, err := httpListener()
		if err != nil {
			t.Logf("error from http server: %+v", err)
		}
		reqChan <- req

		if cmd == nil {
			return
		}
		err = cmd.Process.Kill()
		if err != nil {
			t.Logf("could not kill process: %+v", err)
		}
	}()

	for _, dir := range []string{"/proc/self", "/persist/status"} {
		err := os.MkdirAll(filepath.Join("/out", dir), 0700)
		if err != nil {
			t.Fatal(err)
		}
	}

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

	cmd = exec.Command("/usr/bin/collect-info.sh", "-u", uploadServer)
	cmd.Env = cmdEnv
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Chroot: "/out",
	}
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	_ = cmd.Run()

	req := <-reqChan

	return req
}

// TestCollectInfoUpload creates an http server and calls collect-info.sh to upload the tarball to it
func TestCollectInfoUpload(t *testing.T) {
	defer cleanup(t)

	uploadServer := "http://localhost:8080"
	cmdEnv := []string{"AUTHORIZATION=Bearer Vm0weGQxSXhiRmRXV0d4V1YwZDRWRmxyVm5kVmJGcHlWV3RLVUZWVU1Eaz0="}

	req := runCollectInfo(t, uploadServer, cmdEnv, listenHTTP)
	t.Logf("req: %+v", req)

	if req.Header["Authorization"][0] != "Bearer Vm0weGQxSXhiRmRXV0d4V1YwZDRWRmxyVm5kVmJGcHlWV3RLVUZWVU1Eaz0=" {
		t.Fatalf("authorization header wrong or not set - was %+v", req.Header["Authorization"])
	}

	if !strings.Contains(req.URL.Path, "123456") {
		t.Fatalf("http file path does not contain uuid; req: %+v", req)
	}

	dirEntries, err := os.ReadDir("/out/persist/eve-info")
	if err != nil {
		t.Fatalf("could not read dir /out/persist/eve-info: %v", err)
	}

	if len(dirEntries) > 0 {
		t.Fatalf("expected collect-info tarball to be cleaned up, but got %+v", dirEntries)
	}
}

// TestCollectInfoFailingUpload - fails to upload the tarball and checks that it is not deleted
func TestCollectInfoFailingUpload(t *testing.T) {
	defer cleanup(t)

	uploadServer := "http://localhost:8080"
	cmdEnv := []string{"AUTHORIZATION=Bearer Vm0weGQxSXhiRmRXV0d4V1YwZDRWRmxyVm5kVmJGcHlWV3RLVUZWVU1Eaz0="}

	req := runCollectInfo(t, uploadServer, cmdEnv, func() (*http.Request, error) { return nil, nil })
	t.Logf("req: %+v", req)

	dirEntries, err := os.ReadDir("/out/persist/eve-info")
	if err != nil {
		t.Fatalf("could not read dir /persist/eve-info: %v", err)
	}

	if len(dirEntries) < 1 {
		t.Fatalf("expected collect-info tarball to NOT be cleaned up, but got %+v", dirEntries)
	}
}
