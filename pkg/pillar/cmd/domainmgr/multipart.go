// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handle MIME multi-part messages to create cloud-init directory
// structure

package domainmgr

import (
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
)

// handleMIMEMultipart returns true if this is a MIME multipart
// and if so it takes it apart and writes it to dir.
// If allowFullFilenamePaths is set it allows directory creation; otherwise
// any directory part of the filename is silently ignored.
// It returns errors if a filename tries to escape the dir, and also
// errors if the MIME multi-part is malformed
func handleMimeMultipart(dir string, ciStr string, allowFullFilenamePaths bool) (bool, error) {
	r := strings.NewReader(ciStr)
	msg, err := mail.ReadMessage(r)
	if err != nil {
		log.Noticef("ReadMessage failed: %v", err)
		return false, nil
	}
	ct := msg.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		log.Noticef("ParseMediaType %s failed: %v", ct, err)
		return false, nil
	}
	boundary, ok := params["boundary"]
	if !ok {
		log.Noticef("Missing boundary param in %s", ct)
		return false, nil
	}
	log.Noticef("Found mediaType %s params %v", mediaType, params)
	if !strings.HasPrefix(mediaType, "multipart/") {
		log.Noticef("Not multipart media type: %s", mediaType)
		return false, nil
	}
	mr := multipart.NewReader(msg.Body, boundary)
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			return true, nil
		}
		if err != nil {
			err := fmt.Errorf("NextPart failed: %v", err)
			log.Error(err.Error())
			return true, err
		}
		var filename string
		if allowFullFilenamePaths {
			// Note that p.FileName() now excludes the directory part of
			// the filename to conform with RFC 7578, but we need that to
			// be able to layout the CDROM image so we extract the
			// field directly. Note that we check that we use filepath.Clean
			// to avoid escapes outside of the dir.
			v := p.Header.Get("Content-Disposition")
			_, dispositionParams, err := mime.ParseMediaType(v)
			if err != nil {
				dispositionParams = make(map[string]string)
			}
			filename = dispositionParams["filename"]
		} else {
			filename = p.FileName()
		}
		if filename == "" {
			err := fmt.Errorf("Empty filename field")
			log.Error(err.Error())
			return true, err
		}
		// Note that Join + Clean collapses any .. in path
		// but could still end up with leading ../ in path
		// so we check it starts with the dir.
		filename = filepath.Clean(filepath.Join(dir, filename))
		if !strings.HasPrefix(filename, dir) {
			err := fmt.Errorf("Filename tried to escape: orig %s derived %s",
				p.FileName(), filename)
			log.Error(err.Error())
			return true, err
		}
		dirname := filepath.Dir(filename)
		err = os.MkdirAll(dirname, 0700)
		if err != nil {
			err := fmt.Errorf("MkdirAll failed: %v", err)
			log.Error(err.Error())
			return true, err
		}
		w, err := os.Create(filename)
		if err != nil {
			err := fmt.Errorf("Create(%s) failed: %v", filename, err)
			log.Error(err.Error())
			return true, err
		}
		defer w.Close()

		filelen, err := io.Copy(w, p)
		if err != nil {
			err := fmt.Errorf("Copy(%s) failed: %v", filename, err)
			log.Error(err.Error())
			return true, err
		}
		log.Noticef("Wrote filename %s with %d bytes",
			filename, filelen)
	}
}
