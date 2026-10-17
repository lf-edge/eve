// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"fmt"
	"io"
	"net/http"

	"github.com/pin/tftp/v3"
)

// newImgServerTFTPServer returns a TFTP server serving th.imgServerDir over
// the given connection.
//
// Single-port mode keeps every reply on the same conn/conntrack flow as the
// client's original RRQ. Without it, the library answers each transfer from a
// fresh ephemeral port, which the SDN's NAT (conntrack has no TFTP ALG
// loaded) treats as an unrelated new flow and masquerades with the wrong
// source IP, so PXE ROMs -- which validate that TFTP replies come from the
// server IP they contacted -- silently discard them.
func (th *TestHarness) newImgServerTFTPServer() *tftp.Server {
	server := tftp.NewServer(th.imgServerTFTPReadHandler(), nil)
	server.EnableSinglePort()
	return server
}

// imgServerTFTPReadHandler returns a TFTP read-request handler serving files
// from th.imgServerDir, the same directory and path convention (relative to
// imgServerDir) the plain HTTP image server already uses (see Init's
// imgServerMux/http.FileServer): a netboot artifact reachable at
// http://<imgServerIP>:<imgServerPort>/<path> is reachable at that same
// <path> over TFTP too. Reuses http.Dir's path handling (rooting under
// imgServerDir, rejecting attempts to escape it) rather than reimplementing it.
func (th *TestHarness) imgServerTFTPReadHandler() func(string, io.ReaderFrom) error {
	dir := http.Dir(th.imgServerDir)
	return func(filename string, rf io.ReaderFrom) error {
		f, err := dir.Open(filename)
		if err != nil {
			th.log.Warnf("TFTP: failed to open %q: %v", filename, err)
			return fmt.Errorf("failed to open %q: %w", filename, err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				th.log.Warnf("TFTP: failed to close %s: %v", filename, err)
			}
		}()
		if _, err := rf.ReadFrom(f); err != nil {
			th.log.Warnf("TFTP: failed to serve %q: %v", filename, err)
			return err
		}
		return nil
	}
}
