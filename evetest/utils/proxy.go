// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"io"
	"time"

	"github.com/sirupsen/logrus"
)

// Pipe represents a bidirectional data channel that can send and receive
// arbitrary byte slices. It abstracts a transport layer such as a TCP
// connection, a Unix socket, gRPC stream, etc.
type Pipe interface {
	// Name returns a human-readable identifier for the pipe, used only for logging.
	Name() string

	// Recv reads data from the pipe and returns the received bytes.
	// It may block until data becomes available or an error occurs.
	// If the connection is closed gracefully, it should return io.EOF.
	Recv() (data []byte, err error)

	// Send writes data to the pipe and returns the number of bytes written.
	// It may block until the data is fully transmitted or an error occurs.
	Send(data []byte) (n int, err error)
}

// RunPipeProxy connects two Pipe instances and forwards data between them
// bidirectionally. Data received on one pipe is sent to the other, and vice versa.
//
// The function runs two concurrent goroutines—one for each direction—and
// returns when either direction ends (due to closure or error).
func RunPipeProxy(ctx context.Context, log *logrus.Entry, proxyName string,
	pipe1, pipe2 Pipe) {
	errCh := make(chan error, 2)

	goTaskCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go runSingleDirPipeProxy(goTaskCtx, log, proxyName, errCh, pipe1, pipe2)
	go runSingleDirPipeProxy(goTaskCtx, log, proxyName, errCh, pipe2, pipe1)
	log.Debugf("Started %s proxy", proxyName)

	// Wait for either direction to finish
	select {
	case err := <-errCh:
		if err != nil {
			log.Warnf("%s proxy ended with error: %v", proxyName, err)
		} else {
			log.Debugf("%s proxy ended gracefully", proxyName)
		}
		return
	case <-ctx.Done():
		log.Debugf("%s proxy context is done: %v", proxyName, ctx.Err())
	}
}

// runSingleDirPipeProxy continuously reads data from one pipe (fromPipe)
// and writes it to another (toPipe). It retries transient errors with
// a simple linear backoff and terminates if too many consecutive errors occur.
//
// When fromPipe returns io.EOF, it signals a graceful shutdown through errChan.
func runSingleDirPipeProxy(ctx context.Context, log *logrus.Entry, proxyName string,
	errChan chan error, fromPipe, toPipe Pipe) {
	var data []byte
	errorCount := 0
	const maxErrors = 10

	for {
		if err := ctx.Err(); err != nil {
			log.Warnf("%s proxy (from %s): %v", proxyName, fromPipe.Name(), err)
			errChan <- err
			return
		}
		if len(data) == 0 {
			var err error
			data, err = fromPipe.Recv()
			if err != nil {
				if err == io.EOF {
					log.Debugf("%s proxy (from %s): EOF", proxyName, fromPipe.Name())
					errChan <- nil
					return
				}
				log.Debugf("%s proxy: %s receive error: %v",
					proxyName, fromPipe.Name(), err)

				errorCount++
				if errorCount >= maxErrors {
					err = fmt.Errorf("receive from %s failed %d times: %w",
						fromPipe.Name(), errorCount, err)
					log.Warnf("%s proxy (from %s): %v", proxyName, fromPipe.Name(), err)
					errChan <- err
					return
				}
				waitOnErr(errorCount)
				continue
			}
			errorCount = 0 // reset on success
		}
		if len(data) > 0 {
			n, err := toPipe.Send(data)
			if err != nil {
				log.Debugf("%s proxy (to %s): send error: %v",
					proxyName, toPipe.Name(), err)

				errorCount++
				if errorCount >= maxErrors {
					err = fmt.Errorf("send to %s failed %d times: %w",
						toPipe.Name(), errorCount, err)
					log.Warnf("%s proxy (to %s): %v", proxyName, toPipe.Name(), err)
					errChan <- err
					return
				}
				waitOnErr(errorCount)
				continue
			}
			data = data[n:]
			errorCount = 0 // reset on success
		}
	}
}

func waitOnErr(errCounter int) {
	time.Sleep(time.Duration(errCounter*50) * time.Millisecond)
}

// DataGetter is a constraint for gRPC response types that can be used
// with GrpcPipe. Any response type must implement GetData() to allow
// the pipe to extract the payload as a byte slice.
type DataGetter interface {
	GetData() []byte
}

// GrpcClientPipe turns client's gRPC stream into Pipe.
// Res must implement DataGetter. We cannot enforce this at compile time using
// DataGetter instead of "any" because of pointer/value mismatches between
// grpc.BidiStreamingClient and the protobuf-generated response type.
type GrpcClientPipe[Req any, Res any] struct {
	MakeRequest func(data []byte) *Req
	Stream      grpc.BidiStreamingClient[Req, Res]
}

// Name of the pipe.
func (p GrpcClientPipe[Req, Res]) Name() string {
	return "gRPC client stream"
}

// Recv receives data from the server.
func (p GrpcClientPipe[Req, Res]) Recv() ([]byte, error) {
	res, err := p.Stream.Recv()
	if err != nil || res == nil {
		return nil, err
	}
	dataGetter, ok := any(res).(DataGetter)
	if !ok {
		return nil, fmt.Errorf("grpc response does not implement DataGetter")
	}
	return dataGetter.GetData(), nil
}

// Send sends data to the server.
func (p GrpcClientPipe[Req, Res]) Send(data []byte) (int, error) {
	err := p.Stream.Send(p.MakeRequest(data))
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

// GrpcServerPipe turns server's gRPC stream into Pipe.
// Req must implement DataGetter. We cannot enforce this at compile time using
// DataGetter instead of "any" because of pointer/value mismatches between
// grpc.BidiStreamingClient and the protobuf-generated response type.
type GrpcServerPipe[Req any, Res any] struct {
	MakeResponse func(data []byte) *Res
	Stream       grpc.BidiStreamingServer[Req, Res]
}

// Name of the pipe.
func (p GrpcServerPipe[Req, Res]) Name() string {
	return "gRPC server stream"
}

// Recv receives data from the client.
func (p GrpcServerPipe[Req, Res]) Recv() ([]byte, error) {
	req, err := p.Stream.Recv()
	if err != nil || req == nil {
		return nil, err
	}
	dataGetter, ok := any(req).(DataGetter)
	if !ok {
		return nil, fmt.Errorf("grpc request does not implement DataGetter")
	}
	return dataGetter.GetData(), nil
}

// Send sends data to the client.
func (p GrpcServerPipe[Req, Res]) Send(data []byte) (int, error) {
	err := p.Stream.Send(p.MakeResponse(data))
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

// ReadWriterPipe turns io.ReadWriter into Pipe.
type ReadWriterPipe struct {
	PipeName string
	RW       io.ReadWriter
	Buf      []byte
}

// Name of the pipe.
func (p ReadWriterPipe) Name() string {
	return p.PipeName
}

// Recv receives data from the tun device.
func (p ReadWriterPipe) Recv() (data []byte, err error) {
	n, err := p.RW.Read(p.Buf)
	if err != nil {
		return nil, err
	}
	return p.Buf[:n], nil
}

// Send sends data to the tun device.
func (p ReadWriterPipe) Send(data []byte) (n int, err error) {
	return p.RW.Write(data)
}
