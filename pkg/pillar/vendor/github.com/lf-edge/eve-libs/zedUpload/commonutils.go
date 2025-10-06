// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedUpload

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lf-edge/eve-libs/nettrace"
	ntStore "github.com/lf-edge/eve-libs/nettraceStorage"
)

const (
	//SingleMB represents data size of 1MB
	SingleMB int64 = 1024 * 1024
)

const (
	tcpHandshakeTimeout   = 30 * time.Second
	tcpKeepAliveInterval  = 30 * time.Second
	maxIdleConns          = 100
	idleConnTimeout       = 90 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	expectContinueTimeout = 1 * time.Second
	enableOffload         = true // or false

)

// ChunkData contains the details of Chunks being downloaded
type ChunkData struct {
	Size  int64  // complete size to upload/download
	Chunk []byte // chunk data being uploaded/downloaded
	EOF   bool   // denotes last chunk of the file
}

func processChunkByChunk(readCloser io.ReadCloser, size int64, chunkChan chan ChunkData) error {
	fmt.Println("processChunkByChunk started", size)
	var processed int64
	var eof bool
	for processed < size {
		var rbuf bytes.Buffer
		bufferSize := size - processed
		if bufferSize > SingleMB {
			bufferSize = SingleMB
		} else {
			eof = true
		}
		written, err := io.CopyN(&rbuf, readCloser, int64(bufferSize))
		if err != nil {
			return err
		}
		chunkChan <- ChunkData{Size: size, Chunk: rbuf.Bytes(), EOF: eof}
		processed += written
	}
	readCloser.Close()
	return nil
}

// httpClientWrapper wraps either the standard or the traced HTTP client.
type httpClientWrapper struct {
	// wrapped client
	client       *http.Client
	tracedClient *nettrace.HTTPClient
	// config
	srcIP       net.IP
	withCerts   bool
	certs       [][]byte
	proxy       *url.URL
	withTracing bool
	tracingOpts []nettrace.TraceOpt
	// initialization
	initOnce        sync.Once
	initErr         error
	nettraceSink    *ntStore.BoltBatchSink
	nettraceDirPath string

	sessionUUID string
}

func (c *httpClientWrapper) unwrap() (*http.Client, error) {
	c.initOnce.Do(func() {
		var tlsConfig *tls.Config
		if c.withCerts {
			caCertPool := x509.NewCertPool()
			for _, pem := range c.certs {
				if !caCertPool.AppendCertsFromPEM(pem) {
					c.initErr = fmt.Errorf("failed to append trusted cert")
					return
				}
			}
			tlsConfig = &tls.Config{RootCAs: caCertPool}
		}

		if c.withTracing {
			cfg := nettrace.HTTPClientCfg{
				SourceIP:              c.srcIP,
				TCPHandshakeTimeout:   tcpHandshakeTimeout,
				TCPKeepAliveInterval:  tcpKeepAliveInterval,
				MaxIdleConns:          maxIdleConns,
				IdleConnTimeout:       idleConnTimeout,
				TLSHandshakeTimeout:   tlsHandshakeTimeout,
				ExpectContinueTimeout: expectContinueTimeout,
				Proxy:                 http.ProxyURL(c.proxy),
				TLSClientConfig:       tlsConfig,
			}

			// Ensure folder exists for the sink DB.
			if err := os.MkdirAll(c.nettraceDirPath, 0o755); err != nil {
				c.initErr = fmt.Errorf("create %s: %w", c.nettraceDirPath, err)
				return
			}

			// Create session UUID (string) if not already set
			if c.sessionUUID == "" {
				c.sessionUUID = uuid.NewString()
			}
			opts := make([]nettrace.TraceOpt, 0, len(c.tracingOpts)+1)
			opts = append(opts, c.tracingOpts...)

			// enableOffload decides whether we stream to Bolt via WithBatchOffload.
			// Drive this from your config/flag.
			if enableOffload {
				// Make sure the folder exists.
				if err := os.MkdirAll(c.nettraceDirPath, 0o755); err != nil {
					c.initErr = fmt.Errorf("create %s: %w", c.nettraceDirPath, err)
					return
				}
				// One DB per session.
				dbPath := fmt.Sprintf("%s/nettrace_%s.db", c.nettraceDirPath, c.sessionUUID)

				sink, err := ntStore.NewBoltBatchSink(dbPath)
				if err != nil {
					c.initErr = fmt.Errorf("failed to create nettrace sink: %w", err)
					return
				}
				c.nettraceSink = sink // remember it for later ExportToJSON / Close

				// Add the batch offload so server streams to our sink.
				opts = append(opts, &nettrace.WithBatchOffload{
					Callback:          sink.Handler(),
					Threshold:         1000, // per-map threshold
					FinalFlushOnClose: true, // flush leftovers on Close()
				})
			} else {
				// Pure in-memory path — no sink, no DB.
				c.nettraceSink = nil
			}

			traceClient, err := nettrace.NewHTTPClient(cfg, c.sessionUUID, opts...)
			if err != nil {
				c.initErr = fmt.Errorf("failed to create HTTP client with tracing: %w", err)
				traceClient.Close()
				return
			}
			c.tracedClient = traceClient

		} else {
			// ----- existing non-tracing branch unchanged -----
			dialer := &net.Dialer{
				Timeout:   tcpHandshakeTimeout,
				KeepAlive: tcpKeepAliveInterval,
			}
			if c.srcIP != nil {
				localTCPAddr := &net.TCPAddr{IP: c.srcIP}
				localUDPAddr := &net.UDPAddr{IP: c.srcIP}
				resolverDial := func(ctx context.Context, network, address string) (net.Conn, error) {
					switch network {
					case "udp", "udp4", "udp6":
						d := net.Dialer{LocalAddr: localUDPAddr}
						return d.Dial(network, address)
					case "tcp", "tcp4", "tcp6":
						d := net.Dialer{LocalAddr: localTCPAddr}
						return d.Dial(network, address)
					default:
						return nil, fmt.Errorf("unsupported address type: %v", network)
					}
				}
				resolver := &net.Resolver{
					PreferGo:     true,
					StrictErrors: false,
					Dial:         resolverDial,
				}
				dialer.LocalAddr = localTCPAddr
				dialer.Resolver = resolver
			}
			client := &http.Client{
				Transport: &http.Transport{
					Proxy:                 http.ProxyURL(c.proxy),
					DialContext:           dialer.DialContext,
					MaxIdleConns:          maxIdleConns,
					IdleConnTimeout:       idleConnTimeout,
					TLSHandshakeTimeout:   tlsHandshakeTimeout,
					ExpectContinueTimeout: expectContinueTimeout,
				},
			}
			if tlsConfig != nil {
				client.Transport.(*http.Transport).TLSClientConfig = tlsConfig
			}
			c.client = client
		}
	})

	if c.initErr != nil {
		return nil, c.initErr
	}

	client := c.client
	if c.withTracing {
		client = c.tracedClient.Client
	}
	return client, nil
}

func (c *httpClientWrapper) withBindIntf(intf string) error {
	localAddr := getSrcIPFromInterface(intf)
	if localAddr != nil {
		c.srcIP = localAddr
		return nil
	}
	return fmt.Errorf("failed to get the address for interface %s", intf)
}

func (c *httpClientWrapper) withSrcIP(localAddr net.IP) error {
	c.srcIP = localAddr
	return nil
}

func (c *httpClientWrapper) withTrustedCerts(certs [][]byte) error {
	c.withCerts = true
	c.certs = certs
	return nil
}

func (c *httpClientWrapper) withProxy(proxy *url.URL) error {
	c.proxy = proxy
	return nil
}

func (c *httpClientWrapper) withNetTracing(opts ...nettrace.TraceOpt) error {
	c.tracingOpts = opts
	c.withTracing = true
	return nil
}

func (c *httpClientWrapper) getNetTrace(description string) (
	nettrace.AnyNetTrace, []nettrace.PacketCapture, error) {
	if !c.withTracing {
		return nil, nil, fmt.Errorf("network tracing is not enabled")
	}
	if c.tracedClient == nil {
		return nil, nil, nil
	}

	httpTrace, packetCapture, err := c.tracedClient.GetTrace(description)
	if err != nil {
		return nil, nil, err
	}

	jsonPath := filepath.Join(c.nettraceDirPath, fmt.Sprintf("nettrace_%s.json", c.sessionUUID))
	if c.nettraceSink != nil {
		// Using batch-offload + Bolt sink
		err = c.nettraceSink.ExportToJSON(jsonPath, httpTrace.NetTrace)
	} else {
		// No sink: dump the in-memory trace directly
		err = c.tracedClient.ExportHTTPTraceToJSON(jsonPath, httpTrace)
	}
	if err != nil {
		return nil, nil, err
	}

	// Delete db file
	if c.nettraceSink != nil {
		if err := c.nettraceSink.DeleteDBFile(); err != nil {
			return nil, nil, err
		}
	}

	httpTrace.SessionUUID = c.sessionUUID
	return httpTrace, packetCapture, err
}

func (c *httpClientWrapper) close() error {
	if c.withTracing && c.tracedClient != nil {
		return c.tracedClient.Close()
	}
	return nil
}

// given interface get the ip
func getSrcIPFromInterface(intf string) net.IP {
	ief, err := net.InterfaceByName(intf)
	if err == nil {
		addrs, err := ief.Addrs()
		if err == nil {
			localAddr, _, err := net.ParseCIDR(addrs[0].String())
			if err == nil {
				return localAddr
			}
		}
	}
	return nil
}
