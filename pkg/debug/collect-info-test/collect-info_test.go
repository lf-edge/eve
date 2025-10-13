// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func listenHTTP(method string) (*http.Request, io.Reader, error) {
	var serverShutdown sync.Mutex
	var s *http.Server
	sm := http.NewServeMux()
	var req *http.Request
	var body bytes.Buffer
	var bodyCloseErr error
	var ioCopyErr error
	var shutdownErr error

	sm.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r.Body != nil {
				bodyCloseErr = r.Body.Close()
			}
			go func() {
				shutdownErr = s.Shutdown(context.Background())
				serverShutdown.Unlock()
			}()
		}()

		if r.Method != method {
			http.Error(w, fmt.Sprintf("wrong method, allowed: %s, got %s", method, r.Method), http.StatusMethodNotAllowed)
			return
		}
		req = r

		if req.Body != nil {
			_, ioCopyErr = io.Copy(&body, req.Body)
		}

		http.Error(w, "Bye", http.StatusOK)

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
		return nil, nil, bodyCloseErr
	}
	if shutdownErr != nil {
		return nil, nil, shutdownErr
	}
	if ioCopyErr != nil {
		return nil, nil, ioCopyErr
	}

	return req, &body, nil
}

func cleanup(t *testing.T) {
	for _, dir := range []string{"/proc/self", "/persist"} {
		err := os.RemoveAll(filepath.Join("/out", dir))
		if err != nil {
			t.Fatal(err)
		}
	}
}

func preparePersist(t *testing.T) {
	for _, dir := range []string{"/proc/self", "/persist/status", "/persist/tmp", "/run"} {
		err := os.MkdirAll(filepath.Join("/out", dir), 0700)
		if err != nil {
			t.Fatal(err)
		}
	}
	err := os.WriteFile("/out/run/eve-hv-type", []byte("gotest"), 0600)
	if err != nil {
		t.Fatalf("could not write /out/run/eve-hv-type: %v", err)
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
}

func runCollectInfo(t *testing.T, uploadServer string, cmdEnv []string, httpListener func() (*http.Request, io.Reader, error)) (*http.Request, io.Reader) {
	var cmd *exec.Cmd
	reqChan := make(chan *http.Request)
	bodyChan := make(chan io.Reader)

	preparePersist(t)

	go func() {
		req, body, err := httpListener()
		if err != nil {
			t.Logf("error from http server: %+v", err)
		}
		reqChan <- req
		bodyChan <- body

		if cmd == nil {
			return
		}
		err = cmd.Process.Kill()
		if err != nil {
			t.Logf("could not kill process: %+v", err)
		}
	}()

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
	body := <-bodyChan

	return req, body
}

// TestCollectInfoUploadPUTFailover creates an http server and calls collect-info.sh to upload the tarball to it
// it only accepts http PUT
func TestCollectInfoUploadPUTFailover(t *testing.T) {
	defer cleanup(t)

	uploadServer := "http://localhost:8080"
	cmdEnv := []string{"AUTHORIZATION=Bearer Vm0weGQxSXhiRmRXV0d4V1YwZDRWRmxyVm5kVmJGcHlWV3RLVUZWVU1Eaz0="}

	req, _ := runCollectInfo(t, uploadServer, cmdEnv, func() (*http.Request, io.Reader, error) {
		var req *http.Request
		var err error
		var body io.Reader
		for req == nil {
			req, body, err = listenHTTP("PUT")
			t.Logf("req: %+v, err: %+v", req, err)
		}
		return req, body, err
	})

	if req.Method != "PUT" {
		t.Fatalf("expected http method PUT, but got %s", req.Method)
	}
}

// TestCollectInfoUpload creates an http server and calls collect-info.sh to upload the tarball to it
func TestCollectInfoUpload(t *testing.T) {
	defer cleanup(t)

	var eveHvType string

	uploadServer := "http://localhost:8080"
	cmdEnv := []string{"AUTHORIZATION=Bearer Vm0weGQxSXhiRmRXV0d4V1YwZDRWRmxyVm5kVmJGcHlWV3RLVUZWVU1Eaz0="}

	req, body := runCollectInfo(t, uploadServer, cmdEnv, func() (*http.Request, io.Reader, error) {
		return listenHTTP("POST")
	})
	t.Logf("req: %+v", req)

	if req.Header["Authorization"][0] != "Bearer Vm0weGQxSXhiRmRXV0d4V1YwZDRWRmxyVm5kVmJGcHlWV3RLVUZWVU1Eaz0=" {
		t.Fatalf("authorization header wrong or not set - was %+v", req.Header["Authorization"])
	}

	if req.Body == nil {
		t.Fatalf("request body empty")
	}

	gz, err := gzip.NewReader(body)
	if err != nil {
		t.Fatalf("could not initialize gzip reader: %+v", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("next tar header failed: %v", err)
		}

		t.Logf("- %s\n", hdr.Name)
		if filepath.Base(hdr.Name) == "eve-hv-type" {
			bs, err := io.ReadAll(tr)
			if err != nil {
				t.Fatalf("could not read from uploaded tar file: %v", err)
			}

			eveHvType = string(bs)
		}
	}

	if eveHvType != "gotest" {
		t.Fatalf("wrong eve-hv-type file content in collect-info tar file; expected 'gotest', got '%s'", eveHvType)
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

	req, _ := runCollectInfo(t, uploadServer, cmdEnv, func() (*http.Request, io.Reader, error) { return nil, nil, nil })
	t.Logf("req: %+v", req)

	dirEntries, err := os.ReadDir("/out/persist/eve-info")
	if err != nil {
		t.Fatalf("could not read dir /persist/eve-info: %v", err)
	}

	if len(dirEntries) < 1 {
		t.Fatalf("expected collect-info tarball to NOT be cleaned up, but got %+v", dirEntries)
	}
}
