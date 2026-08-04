// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func TestResolveSoftSerialGeneratesWhenEmpty(t *testing.T) {
	got := resolveSoftSerial("")
	if got == "" {
		t.Fatal("resolveSoftSerial(\"\") returned an empty serial")
	}
	if _, err := uuid.Parse(got); err != nil {
		t.Errorf("generated serial %q is not a UUID: %v", got, err)
	}
}

// TestResolveSoftSerialIsUniquePerCall is the property that keeps cluster nodes
// distinct: the EVE container used to generate a serial per build, but it now
// runs once per template, so the broker must generate one per working copy.
func TestResolveSoftSerialIsUniquePerCall(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		s := resolveSoftSerial("")
		if _, dup := seen[s]; dup {
			t.Fatalf("resolveSoftSerial produced a duplicate serial %q", s)
		}
		seen[s] = struct{}{}
	}
}

func TestResolveSoftSerialHonoursRequested(t *testing.T) {
	const want = "my-fixed-serial"
	if got := resolveSoftSerial(want); got != want {
		t.Errorf("resolveSoftSerial(%q) = %q, want it passed through", want, got)
	}
}

// TestMcopyArgs pins the command shape against pkg/eve/runme.sh:337,
//
//	mcopy -o -i /bits/config.img -s /in/* ::/
//
// with the shell glob replaced by an explicit list of the config dir's
// top-level entries.
func TestMcopyArgs(t *testing.T) {
	got := mcopyArgs("/work/cfg.img", []string{"/in/server", "/in/GlobalConfig"})
	want := []string{"-o", "-i", "/work/cfg.img", "-s", "/in/server", "/in/GlobalConfig", "::/"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("mcopyArgs() = %v, want %v", got, want)
	}
}

func TestMakeEVEConfigDirWritesSoftSerial(t *testing.T) {
	parent := t.TempDir()
	dir, err := makeEVEConfigDir(parent, nil, nil, "serial-1234")
	if err != nil {
		t.Fatalf("makeEVEConfigDir: %v", err)
	}
	if dir == "" {
		t.Fatal("makeEVEConfigDir returned no directory despite a soft serial")
	}
	data, err := os.ReadFile(filepath.Join(dir, "soft_serial"))
	if err != nil {
		t.Fatalf("read soft_serial: %v", err)
	}
	if string(data) != "serial-1234" {
		t.Errorf("soft_serial = %q, want %q", data, "serial-1234")
	}
}

// selfSignedTestCertPEM generates a throwaway self-signed certificate PEM
// block, so tests needing a valid certificate don't depend on a fixture file.
func selfSignedTestCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "evetest-proxy-ca"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestMakeEVEConfigDirNilConfigStillWritesProxyCerts covers a nil per-request
// EveConfig combined with broker-wide proxy CA certificates: the certs must
// still be written, since b.proxyCACerts exists independently of any request.
func TestMakeEVEConfigDirNilConfigStillWritesProxyCerts(t *testing.T) {
	certPEM := selfSignedTestCertPEM(t)
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode the generated test CA PEM")
	}
	dir, err := makeEVEConfigDir(t.TempDir(), nil, []*pem.Block{block}, "serial-1")
	if err != nil {
		t.Fatalf("makeEVEConfigDir: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "v2tlsbaseroot-certificates.pem"))
	if err != nil {
		t.Fatalf("proxy CA certs were not written with a nil config: %v", err)
	}
	if len(data) == 0 {
		t.Error("v2tlsbaseroot-certificates.pem is empty")
	}
}

// TestInjectConfigPartitionRejectsOversizedImage covers a config image larger
// than the CONFIG partition: it must fail rather than write past the partition.
func TestInjectConfigPartitionRejectsOversizedImage(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.img")
	if err := os.WriteFile(cfg, make([]byte, 1024), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	err := injectConfigPartition(context.Background(), log,
		filepath.Join(dir, "disk.qcow2"), cfg, gptPartition{Offset: 0, Length: 512})
	if err == nil {
		t.Fatal("expected an error when the config image exceeds the partition")
	}
}

// TestInjectConfigPartitionRejectsWhitespacePath covers a path that qemu-io's
// own tokenizer would split into separate arguments.
func TestInjectConfigPartitionRejectsWhitespacePath(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config file.img")
	if err := os.WriteFile(cfg, make([]byte, 512), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	err := injectConfigPartition(context.Background(), log,
		filepath.Join(dir, "disk.qcow2"), cfg, gptPartition{Offset: 0, Length: 5 << 20})
	if err == nil {
		t.Fatal("expected an error for a config image path containing whitespace")
	}
	if !strings.Contains(err.Error(), "whitespace") {
		t.Errorf("error should name the whitespace problem, got: %v", err)
	}
}

func TestResizeDeviceDiskRejectsShrink(t *testing.T) {
	err := resizeDeviceDisk(context.Background(), "/nonexistent.qcow2", 1<<30, 4<<30)
	if err == nil {
		t.Fatal("expected an error when the requested size is smaller than the image")
	}
	if !strings.Contains(err.Error(), "smaller") {
		t.Errorf("error should explain the shrink, got: %v", err)
	}
}

// TestResizeDeviceDiskNoopWhenEqual covers the common case: no qemu-img call at
// all, so a nonexistent path is fine.
func TestResizeDeviceDiskNoopWhenEqual(t *testing.T) {
	if err := resizeDeviceDisk(context.Background(), "/nonexistent.qcow2", 4<<30, 4<<30); err != nil {
		t.Fatalf("equal sizes should be a no-op, got: %v", err)
	}
	if err := resizeDeviceDisk(context.Background(), "/nonexistent.qcow2", 0, 4<<30); err != nil {
		t.Fatalf("zero request should be a no-op, got: %v", err)
	}
}

// TestResizeDeviceDiskGrowsStandaloneCopy covers the standalone strategy, where
// the device disk is a plain copy of the template rather than an overlay on it.
// A live template is keyed without the disk size, so this resize is the only
// thing that gives such a device the size the test asked for -- a copy that is
// never grown silently boots at the template's size instead.
func TestResizeDeviceDiskGrowsStandaloneCopy(t *testing.T) {
	const haveBytes = 64 << 20
	const wantBytes = 128 << 20
	diskPath := filepath.Join(t.TempDir(), "disk.qcow2")
	out, err := exec.Command("qemu-img", "create", "-f", "qcow2",
		diskPath, strconv.Itoa(haveBytes)).CombinedOutput()
	if err != nil {
		t.Fatalf("qemu-img create: %v: %s", err, out)
	}

	if err := resizeDeviceDisk(
		context.Background(), diskPath, wantBytes, haveBytes); err != nil {
		t.Fatalf("resizeDeviceDisk: %v", err)
	}

	out, err = exec.Command("qemu-img", "info", "--output=json", diskPath).Output()
	if err != nil {
		t.Fatalf("qemu-img info: %v", err)
	}
	var info struct {
		VirtualSize   int64  `json:"virtual-size"`
		BackingFile   string `json:"backing-filename"`
		ActualSize    int64  `json:"actual-size"`
		ClusterSize   int64  `json:"cluster-size"`
		DirtyFlagFlag bool   `json:"dirty-flag"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		t.Fatalf("parse qemu-img info: %v", err)
	}
	if info.VirtualSize != wantBytes {
		t.Errorf("virtual size = %d, want %d", info.VirtualSize, wantBytes)
	}
	if info.BackingFile != "" {
		t.Errorf("a standalone copy must have no backing file, got %q", info.BackingFile)
	}
}
