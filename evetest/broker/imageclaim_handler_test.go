// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os/exec"
	"testing"
	"time"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type fakeEVEImageStream struct {
	msgs []*api.PushImageChunk
	idx  int
	resp *api.PushImageResponse
}

func (f *fakeEVEImageStream) Recv() (*api.PushImageChunk, error) {
	if f.idx >= len(f.msgs) {
		return nil, io.EOF
	}
	m := f.msgs[f.idx]
	f.idx++
	return m, nil
}

func (f *fakeEVEImageStream) SendAndClose(resp *api.PushImageResponse) error {
	f.resp = resp
	return nil
}

func (f *fakeEVEImageStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeEVEImageStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeEVEImageStream) SetTrailer(metadata.MD)       {}
func (f *fakeEVEImageStream) Context() context.Context     { return context.Background() }
func (f *fakeEVEImageStream) SendMsg(m any) error          { return nil }
func (f *fakeEVEImageStream) RecvMsg(m any) error          { return nil }

func tarEntry(t *testing.T, tw *tar.Writer, name string, data []byte) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
}

// dockerArchiveGz builds the smallest `docker save | gzip` stream that
// `docker load` accepts: one empty layer, tagged with the given names.
func dockerArchiveGz(t *testing.T, tags ...string) []byte {
	t.Helper()
	var layer bytes.Buffer
	ltw := tar.NewWriter(&layer)
	if err := ltw.Close(); err != nil {
		t.Fatal(err)
	}
	diffID := sha256.Sum256(layer.Bytes())
	cfg, err := json.Marshal(map[string]any{
		"architecture": "amd64",
		"os":           "linux",
		"config":       map[string]any{},
		"rootfs": map[string]any{
			"type":     "layers",
			"diff_ids": []string{"sha256:" + hex.EncodeToString(diffID[:])},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal([]map[string]any{{
		"Config": "config.json", "RepoTags": tags, "Layers": []string{"layer.tar"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	tarEntry(t, tw, "layer.tar", layer.Bytes())
	tarEntry(t, tw, "config.json", cfg)
	tarEntry(t, tw, "manifest.json", manifest)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

type fakePullStream struct {
	grpc.ServerStream
	data []byte
}

func (f *fakePullStream) Send(c *api.PullImageChunk) error {
	f.data = append(f.data, c.GetDataGzipChunk()...)
	return nil
}
func (f *fakePullStream) Context() context.Context { return context.Background() }

func pushMsgs(ticket string, data []byte) []*api.PushImageChunk {
	return []*api.PushImageChunk{
		{Payload: &api.PushImageChunk_Request{Request: &api.PushImageRequest{
			ClaimTicket: ticket,
		}}},
		{Payload: &api.PushImageChunk_DataGzipChunk{DataGzipChunk: data}},
	}
}

func TestEVEImageClaimAndUpload(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker is not available: %v", err)
	}
	ref := &api.ImageRef{
		Repo:       "evetest-claimtest/eve",
		Version:    "0.0.0-pr1-abcd1234",
		Hypervisor: api.HypervisorType_HV_KVM,
		Arch:       api.ArchType_ARCH_AMD64,
	}
	const name = "evetest-claimtest/eve:0.0.0-pr1-abcd1234-kvm-amd64"
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "-f", name).Run() })

	b := &broker{
		globalLog:      logrus.New(),
		supportedArchs: []api.ArchType{api.ArchType_ARCH_AMD64},
		imageUsage:     newImageUsageTracker(t.TempDir()),
		imageClaims:    newImageClaims(imageClaimStartLease, imageClaimProgressLease),
		imageUploads:   make(map[string]chan struct{}),
		sessions: map[string]*session{
			"c1": {clientID: "c1", log: logrus.NewEntry(logrus.New())},
		},
	}
	ctx := context.Background()
	claim := func() *api.ClaimEVEImageUploadResponse {
		t.Helper()
		resp, err := b.ClaimEVEImageUpload(ctx, &api.ClaimEVEImageUploadRequest{Image: ref})
		if err != nil {
			t.Fatalf("ClaimEVEImageUpload: %v", err)
		}
		return resp
	}

	first := claim()
	if first.State != api.ImageUploadClaimState_IMAGE_UPLOAD_CLAIM_GRANTED || first.Ticket == "" {
		t.Fatalf("first claim: %+v", first)
	}
	if second := claim(); second.State != api.ImageUploadClaimState_IMAGE_UPLOAD_CLAIM_HELD {
		t.Fatalf("second claim: %+v", second)
	}

	// A stale or foreign ticket cannot upload.
	bad := &fakeEVEImageStream{msgs: pushMsgs("not-the-ticket", dockerArchiveGz(t, name))}
	if err := b.PushEVEContainerImage(bad); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("upload with a wrong ticket: %v", err)
	}

	// An archive that lacks the claimed tag fails and frees the claim.
	wrongTag := &fakeEVEImageStream{
		msgs: pushMsgs(first.Ticket, dockerArchiveGz(t, "evetest-claimtest/other:x"))}
	if err := b.PushEVEContainerImage(wrongTag); err == nil {
		t.Fatal("upload of an archive without the claimed tag succeeded")
	}
	_ = exec.Command("docker", "image", "rm", "-f", "evetest-claimtest/other:x").Run()
	retry := claim()
	if retry.State != api.ImageUploadClaimState_IMAGE_UPLOAD_CLAIM_GRANTED {
		t.Fatalf("claim after a failed upload: %+v", retry)
	}
	if retry.Ticket == first.Ticket {
		t.Fatal("ticket reused after a failed upload")
	}

	good := &fakeEVEImageStream{msgs: pushMsgs(retry.Ticket, dockerArchiveGz(t, name))}
	if err := b.PushEVEContainerImage(good); err != nil {
		t.Fatalf("upload with the ticket: %v", err)
	}
	if got := claim(); got.State != api.ImageUploadClaimState_IMAGE_UPLOAD_CLAIM_PRESENT {
		t.Fatalf("claim after the upload: %+v", got)
	}
	// The image can be pulled back, and an absent one reports NotFound.
	pulled := &fakePullStream{}
	if err := b.PullEVEContainerImage(
		&api.PullEVEImageRequest{ClientId: "c1", Image: ref}, pulled); err != nil {
		t.Fatalf("PullEVEContainerImage: %v", err)
	}
	if zr, err := gzip.NewReader(bytes.NewReader(pulled.data)); err != nil {
		t.Fatalf("pulled data is not gzip: %v", err)
	} else if n, err := io.Copy(io.Discard, zr); err != nil || n == 0 {
		t.Fatalf("pulled archive: %d bytes, %v", n, err)
	}
	absent := &api.ImageRef{Repo: ref.Repo, Version: "absent",
		Hypervisor: ref.Hypervisor, Arch: ref.Arch}
	err := b.PullEVEContainerImage(&api.PullEVEImageRequest{ClientId: "c1", Image: absent}, &fakePullStream{})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("pull of an absent image: %v", err)
	}

	// The claim was released by the upload: releasing again is harmless.
	if _, err := b.ReleaseEVEImageUploadClaim(ctx, &api.ReleaseEVEImageUploadClaimRequest{
		Ticket: retry.Ticket}); err != nil {
		t.Fatalf("ReleaseEVEImageUploadClaim: %v", err)
	}
}

// blockedEVEImageStream delivers the request, then stalls until released, like
// an upload whose client hangs or is partitioned.
type blockedEVEImageStream struct {
	fakeEVEImageStream
	ctx     context.Context
	release chan struct{}
}

func (f *blockedEVEImageStream) Context() context.Context { return f.ctx }

func (f *blockedEVEImageStream) Recv() (*api.PushImageChunk, error) {
	if f.idx >= len(f.msgs) {
		select {
		case <-f.release:
		case <-f.ctx.Done():
		}
		return nil, io.ErrUnexpectedEOF
	}
	return f.fakeEVEImageStream.Recv()
}

// TestEVEImageUploadTakeoverOfStalledHolder is the case the claim lease exists
// for: the holder stalls mid-upload past its lease, another client takes the
// claim over and must complete its own upload without waiting for the stalled
// one, which gets aborted.
func TestEVEImageUploadTakeoverOfStalledHolder(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker is not available: %v", err)
	}
	ref := &api.ImageRef{
		Repo:       "evetest-claimtest/eve",
		Version:    "0.0.0-pr3-abcd1234",
		Hypervisor: api.HypervisorType_HV_KVM,
		Arch:       api.ArchType_ARCH_AMD64,
	}
	const name = "evetest-claimtest/eve:0.0.0-pr3-abcd1234-kvm-amd64"
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "-f", name).Run() })

	claims := newImageClaims(time.Hour, time.Minute)
	now := time.Now()
	claims.now = func() time.Time { return now }
	b := &broker{
		globalLog:      logrus.New(),
		supportedArchs: []api.ArchType{api.ArchType_ARCH_AMD64},
		imageUsage:     newImageUsageTracker(t.TempDir()),
		imageClaims:    claims,
		imageUploads:   make(map[string]chan struct{}),
		sessions:       make(map[string]*session),
	}
	ctx := context.Background()
	first, err := b.ClaimEVEImageUpload(ctx, &api.ClaimEVEImageUploadRequest{Image: ref})
	if err != nil || first.State != api.ImageUploadClaimState_IMAGE_UPLOAD_CLAIM_GRANTED {
		t.Fatalf("first claim: %+v %v", first, err)
	}

	// The holder sends the request and a first chunk of the archive, then stalls.
	stalled := &blockedEVEImageStream{
		fakeEVEImageStream: fakeEVEImageStream{msgs: pushMsgs(first.Ticket, []byte("x"))[:1]},
		ctx:                ctx,
		release:            make(chan struct{}),
	}
	holderDone := make(chan error, 1)
	go func() { holderDone <- b.PushEVEContainerImage(stalled) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		claims.mutex.Lock()
		attached := claims.claims[name].cancel != nil
		claims.mutex.Unlock()
		if attached {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the holder's upload did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}

	now = now.Add(2 * time.Minute) // the (progress) lease lapses; the start lease would not have
	second, err := b.ClaimEVEImageUpload(ctx, &api.ClaimEVEImageUploadRequest{Image: ref})
	if err != nil || second.State != api.ImageUploadClaimState_IMAGE_UPLOAD_CLAIM_GRANTED {
		t.Fatalf("takeover claim: %+v %v", second, err)
	}

	taker := &fakeEVEImageStream{msgs: pushMsgs(second.Ticket, dockerArchiveGz(t, name))}
	if err := b.PushEVEContainerImage(taker); err != nil {
		t.Fatalf("upload after the takeover: %v", err)
	}
	if got, err := b.ClaimEVEImageUpload(ctx, &api.ClaimEVEImageUploadRequest{Image: ref}); err != nil ||
		got.State != api.ImageUploadClaimState_IMAGE_UPLOAD_CLAIM_PRESENT {
		t.Fatalf("claim after the takeover upload: %+v %v", got, err)
	}

	select {
	case err := <-holderDone:
		if err == nil {
			t.Fatal("the stalled holder's upload succeeded")
		}
	case <-time.After(10 * time.Second):
		close(stalled.release)
		t.Fatal("the stalled holder's upload was not aborted by the takeover")
	}
}
