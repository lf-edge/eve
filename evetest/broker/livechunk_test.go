// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"os"
	"testing"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/metadata"
)

// fakeLiveImageStream implements grpc.ClientStreamingServer[PushLiveImageChunk,
// PushLiveImageResponse] by replaying a canned sequence of messages, so
// PushEVELiveImage's receive loop can be driven without a real gRPC server.
type fakeLiveImageStream struct {
	msgs []*api.PushLiveImageChunk
	idx  int
	resp *api.PushLiveImageResponse
}

func (f *fakeLiveImageStream) Recv() (*api.PushLiveImageChunk, error) {
	if f.idx >= len(f.msgs) {
		return nil, io.EOF
	}
	m := f.msgs[f.idx]
	f.idx++
	return m, nil
}

func (f *fakeLiveImageStream) SendAndClose(resp *api.PushLiveImageResponse) error {
	f.resp = resp
	return nil
}

func (f *fakeLiveImageStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeLiveImageStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeLiveImageStream) SetTrailer(metadata.MD)       {}
func (f *fakeLiveImageStream) Context() context.Context     { return context.Background() }
func (f *fakeLiveImageStream) SendMsg(m any) error          { return nil }
func (f *fakeLiveImageStream) RecvMsg(m any) error          { return nil }

// TestPushEVELiveImageSkipsEmptyChunk reproduces the real failure: a metadata
// message followed by a zero-length data chunk (as the client's chunking
// writer used to emit) and then a real chunk. The upload must succeed and the
// staged file must contain exactly the real bytes -- the empty chunk must
// leave no trace.
func TestPushEVELiveImageSkipsEmptyChunk(t *testing.T) {
	dir := t.TempDir()
	b := &broker{
		globalLog: logrus.New(),
		imageDir:  dir,
		sessions: map[string]*session{
			"client1": {clientID: "client1", log: logrus.NewEntry(logrus.New())},
		},
	}

	const sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	realChunk := []byte("hello world, this is the real chunk")
	stream := &fakeLiveImageStream{msgs: []*api.PushLiveImageChunk{
		{Payload: &api.PushLiveImageChunk_Request{Request: &api.PushLiveImageRequest{
			ClientId:  "client1",
			LiveImage: &api.LiveImageRef{Sha256: sha, Version: "1"},
		}}},
		{Payload: &api.PushLiveImageChunk_DataChunk{DataChunk: nil}},
		{Payload: &api.PushLiveImageChunk_DataChunk{DataChunk: realChunk}},
	}}

	if err := b.PushEVELiveImage(stream); err != nil {
		t.Fatalf("PushEVELiveImage: %v", err)
	}
	if stream.resp == nil || stream.resp.AlreadyExists {
		t.Fatalf("unexpected response: %+v", stream.resp)
	}

	got, err := os.ReadFile(liveUploadPath(dir, sha))
	if err != nil {
		t.Fatalf("read staged file: %v", err)
	}
	if string(got) != string(realChunk) {
		t.Fatalf("staged file = %q, want %q", got, realChunk)
	}
}
