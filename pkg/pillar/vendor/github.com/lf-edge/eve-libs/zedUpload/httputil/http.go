// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/lf-edge/eve-libs/zedUpload/types"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/html"
)

const (
	chunkSize  int64 = 64 * 1024
	maxRetries       = 7 // gives ~1m of overall timeout
	maxDelay         = time.Minute
)

// Resp response data from executing commands
type Resp struct {
	List          []string //list of images at given path
	BodyLength    int      // Body length in http response
	ContentLength int64    // Content length in http response
}

var userAgent = "UnityNetworkReporter/" + " (" + runtime.GOOS + " " + runtime.GOARCH + ")"

func getHttpClient() *http.Client {
	tr := &http.Transport{
		TLSNextProto: make(map[string]func(s string, conn *tls.Conn) http.RoundTripper),
	}
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Do _NOT_ follow redirects!
		},
		Transport: tr,
	}
}

func getHref(token html.Token) (ok bool, href string) {
	// Iterate over all of the Token's attributes until we find an "href"
	for _, attr := range token.Attr {
		if attr.Key == "href" {
			href = attr.Val
			ok = true
		}
	}

	return
}

// ExecCmd performs various commands such as "ls", "get", etc.
// Note that "host" needs to contain the URL in the case of a get
func ExecCmd(ctx context.Context, cmd, host, remoteFile, localFile string, objSize int64,
	prgNotify types.StatsNotifChan, client *http.Client, inactivityTimeout time.Duration) (types.UpdateStats, Resp) {
	if ctx == nil {
		ctx = context.Background()
	}
	var imgList []string
	stats := types.UpdateStats{}
	rsp := Resp{}
	if client == nil {
		client = getHttpClient()
	}
	switch cmd {
	case "ls":
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, host, nil)
		if err != nil {
			stats.Error = fmt.Errorf("request failed for ls %s: %s",
				host, err)
			return stats, rsp
		}
		resp, err := client.Do(req)
		if err != nil {
			stats.Error = fmt.Errorf("get failed for ls %s: %s",
				host, err)
			return stats, rsp
		}

		if resp.StatusCode != 200 {
			stats.Error = fmt.Errorf("bad response code for ls %s: %d",
				host, resp.StatusCode)
			return stats, rsp
		}

		tokenizer := html.NewTokenizer(resp.Body)

		for tokenType := tokenizer.Next(); tokenType != html.ErrorToken; tokenType = tokenizer.Next() {
			if tokenType == html.StartTagToken {
				token := tokenizer.Token()
				// Check if the token is an <a> tag
				isAnchor := token.Data == "a"
				if !isAnchor {
					continue
				}
				// Extract the href value, if there is one
				ok, url := getHref(token)
				if !ok {
					continue
				}

				imgList = append(imgList, url)
			}
		}

		resp.Body.Close()
		types.SendStats(prgNotify, stats)
		rsp.List = imgList
		return stats, rsp
	case "get":
		return execCmdGet(ctx, objSize, localFile, host, client, prgNotify, inactivityTimeout)
	case "post":
		file, err := os.Open(localFile)
		if err != nil {
			stats.Error = err
			return stats, rsp
		}
		defer file.Close()
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, err := writer.CreateFormFile(remoteFile, filepath.Base(localFile))
		if err != nil {
			stats.Error = err
			return stats, rsp
		}
		_, err = io.Copy(part, file)
		if err != nil {
			stats.Error = err
			return stats, rsp
		}
		err = writer.Close()
		if err != nil {
			stats.Error = err
			return stats, rsp
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, host, body)
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Content-Type", writer.FormDataContentType())
		resp, err := client.Do(req)
		if err != nil {
			stats.Error = fmt.Errorf("request failed for post %s: %s",
				host, err)
			return stats, rsp
		} else {
			BODY := &bytes.Buffer{}
			_, err := BODY.ReadFrom(resp.Body)
			if err != nil {
				stats.Error = fmt.Errorf("post failed for %s: %s",
					host, err)
				return stats, rsp
			}
			resp.Body.Close()
		}
		Body, _ := io.ReadAll(resp.Body)
		stats.Asize = int64(len(Body))
		types.SendStats(prgNotify, stats)
		rsp.BodyLength = len(Body)
		return stats, rsp
	case "meta":
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, host, nil)
		if err != nil {
			stats.Error = fmt.Errorf("request failed for meta %s: %s",
				host, err)
			return stats, rsp
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Content-Type", "application/octet-stream")

		resp, err := client.Do(req)
		if err != nil {
			stats.Error = fmt.Errorf("head failed for meta %s: %s",
				host, err)
			return stats, rsp
		}
		rsp.ContentLength = resp.ContentLength
		return stats, rsp
	default:
		stats.Error = fmt.Errorf("unknown subcommand: %v", cmd)
		return stats, rsp
	}
}

// execCmdGet executes the get command.
// NOTE: These **must** be named return values, or our defer to modify them will not work.
func execCmdGet(ctx context.Context, objSize int64, localFile string, host string, client *http.Client, prgNotify types.StatsNotifChan, inactivityTimeout time.Duration) (stats types.UpdateStats, rsp Resp) {
	var copiedSize int64

	stats.Size = objSize
	dirErr := os.MkdirAll(filepath.Dir(localFile), 0755)
	if dirErr != nil {
		stats.Error = dirErr
		return stats, Resp{}
	}
	local, fileErr := os.Create(localFile)
	if fileErr != nil {
		stats.Error = fileErr
		return stats, Resp{}
	}
	defer local.Close()

	var errorList []string
	defer func() {
		if len(errorList) > 0 {
			stats.Error = fmt.Errorf("%s: %s", host, strings.Join(errorList, "; "))
		}
	}()
	supportRange := false //is server supports ranges requests, false for the first request
	forceRestart := false
	delay := time.Second
	lastModified := ""
	for attempt := 0; attempt < maxRetries; attempt++ {
		appendToErrorList := func(format string, a ...interface{}) {
			errMsg := fmt.Sprintf(format, a...)
			errorList = append(errorList, fmt.Sprintf("(attempt %d/%d): %v", attempt, maxRetries, errMsg))
			logrus.Warnf("ExecCmd get %s failed (attempt %d/%d): %v", host, attempt, maxRetries, errMsg)
		}
		//check context error on every attempt
		if ctx.Err() != nil {
			appendToErrorList(ctx.Err().Error())
			break
		}
		if attempt > 0 {
			time.Sleep(delay)
			if delay < maxDelay {
				delay = delay * 2
			}
		}

		// restart from the beginning if server do not support ranges or we forced to restart
		if !supportRange || forceRestart {
			err := local.Truncate(0)
			if err != nil {
				appendToErrorList("failed truncate file: %s", err)
				continue
			}
			_, err = local.Seek(0, 0)
			if err != nil {
				appendToErrorList("failed seek file: %s", err)
				continue
			}
			copiedSize = 0
			forceRestart = false
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, host, nil)
		if err != nil {
			appendToErrorList("request failed for get %s: %s", host, err)
			return stats, Resp{}
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Content-Type", "application/octet-stream")

		withRange := false
		//add Range header if server supports it and we already receive data
		if supportRange && copiedSize > 0 {
			withRange = true
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", copiedSize))
		}
		// set the inactivity timer just for retrieving the headers
		if transport, ok := client.Transport.(*http.Transport); ok {
			transport.ResponseHeaderTimeout = inactivityTimeout
		}
		resp, err := client.Do(req)
		if err != nil {
			// break the retries loop and skip the error from
			// http *net.DNSError if the error has the suffix
			// of "no suitable address found"
			if IsNoSuitableAddrErr(err) {
				appendToErrorList(NoSuitableAddrStr)
				break
			}
			// timeout is like any other error, so will do retries
			appendToErrorList("client.Do failed: %s", err)
			continue
		}
		defer resp.Body.Close()

		// supportRange indicates if server supports range requests
		supportRange = resp.Header.Get("Accept-Ranges") == "bytes"

		//if we not receive StatusOK for request without Range header or StatusPartialContent for request with range
		//it indicates that server misconfigured
		if !withRange && resp.StatusCode != http.StatusOK || withRange && resp.StatusCode != http.StatusPartialContent {
			respErr := fmt.Sprintf("bad response code: %d", resp.StatusCode)
			appendToErrorList(respErr)
			//we do not want to process server misconfiguration here
			break
		}
		newLastModified := resp.Header.Get("Last-Modified")
		if lastModified != "" && newLastModified != lastModified {
			// last modified changed, retry from the beginning
			lastModified = newLastModified
			forceRestart = true
			appendToErrorList("last modified changed, do the retry")
			continue
		}
		if resp.StatusCode == http.StatusOK {
			// we received StatusOK which is the response for the whole content, not for the partial one
			rsp.BodyLength = int(resp.ContentLength)
		}
		var written int64

		// use the inactivityReader to trigger failure for the timeouts
		inactivityReader := NewTimeoutReader(inactivityTimeout, resp.Body)
		for {
			var copyErr error

			written, copyErr = io.CopyN(local, inactivityReader, chunkSize)
			copiedSize += written
			stats.Asize = copiedSize

			// possible situations:
			// err != nil && err == io.EOF - end of file, wrap up and return
			// err != nil && err == inactivityTimeout - begin a retry
			// err != nil - wrap up and return
			// err == nil - update stats and keep reading
			switch {
			case copyErr != nil && errors.Is(copyErr, io.EOF) && copiedSize != objSize && objSize != 0:
				appendToErrorList("premature EOF after %d out of %d bytes: %+v", copiedSize, objSize, copyErr)
				return stats, rsp
			case copyErr != nil && errors.Is(copyErr, io.EOF):
				// empty out the error list
				errorList = nil
				return stats, rsp
			case copyErr != nil && errors.Is(copyErr, &ErrTimeout{}):
				// the error comes from timeout
				appendToErrorList("inactivity for %s", inactivityTimeout)
			case copyErr != nil:
				appendToErrorList("error from CopyN after %d out of %d bytes: %v", copiedSize, objSize, copyErr)
				return stats, rsp
			default:
				// no error, so just continue
				types.SendStats(prgNotify, stats)
				continue
			}
			// every other case either returns or continues; if we made it here,
			// break io.CopyN loop, forcing a retry of the outer loop
			break
		}
	}
	return stats, rsp
}
