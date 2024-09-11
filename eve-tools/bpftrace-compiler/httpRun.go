// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func newHTTPRun(host string) *run {
	var hr httpRun

	hr.host = host

	var r run
	r.remoteRun = &hr

	return &r
}

type httpRun struct {
	host string
}

func httpDebugGet(archURL url.URL) []byte {
	resp, err := http.Get(archURL.String())
	if err != nil {
		log.Fatalf("retrieving architecture info via %s failed: %v", archURL.String(), err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("could not read response body: %v", err)
	}
	defer resp.Body.Close()

	return body
}

func (hr *httpRun) lkConf() lkConf {
	linuxkitYmlURL := url.URL{
		Host:   hr.host,
		Scheme: "http",
		Path:   "/debug/info/linuxkit.yml",
	}

	yml := httpDebugGet(linuxkitYmlURL)

	lkc := linuxkitYml2KernelConf(yml)

	return lkc
}

func (hr *httpRun) arch() string {
	archURL := url.URL{
		Host:   hr.host,
		Scheme: "http",
		Path:   "/debug/info/arch",
	}

	archBytes := httpDebugGet(archURL)

	return strings.TrimSpace(string(archBytes))
}

func (hr *httpRun) runBpftrace(aotFile string, timeout time.Duration) error {

	bpftraceURL := url.URL{
		Host:   hr.host,
		Scheme: "http",
		Path:   "/debug/bpftrace",
	}

	pipeReader, pipeWriter := io.Pipe()
	defer pipeReader.Close()

	req, err := http.NewRequest(http.MethodPost, bpftraceURL.String(), pipeReader)
	if err != nil {
		return fmt.Errorf("http request to %s failed: %v", bpftraceURL.String(), err)
	}
	multipartWriter := multipart.NewWriter(pipeWriter)
	req.Header.Add("Content-Type", multipartWriter.FormDataContentType())

	errChan := make(chan error, 1)
	go func() {
		defer pipeWriter.Close()
		tmpFh, err := os.Open(aotFile)
		if err != nil {
			errChan <- err
			return
		}
		defer tmpFh.Close()
		err = multipartWriter.WriteField("timeout", fmt.Sprintf("%d", uint32(timeout.Seconds())))
		if err != nil {
			errChan <- err
			return
		}
		formWriter, err := multipartWriter.CreateFormFile("aot", "bpf.bt")
		if err != nil {
			errChan <- err
			return
		}
		_, err = io.Copy(formWriter, tmpFh)
		if err != nil {
			errChan <- err
			return
		}
		close(errChan)
		err = multipartWriter.Close()
		if err != nil {
			errChan <- err
			return
		}
	}()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("received response %v with error %v", resp, err)
	}
	log.Printf("http multiform resp is %+v\n", resp)

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		fmt.Printf("%s\n", scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("could not read response body: %v", err)
	}

	err = <-errChan
	if err != nil {
		log.Fatal(err)
	}
	err = multipartWriter.Close()
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

func (hr *httpRun) end() {
}
