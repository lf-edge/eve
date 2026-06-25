// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/logger"
	"github.com/lf-edge/eve/evetest/utils"
	"github.com/sirupsen/logrus"
)

// QemuProvider manages the lifecycle of VMs using QEMU directly.
// It creates QEMU processes, TAP devices, bridges, and manages networking
// with dnsmasq used for DNS and DHCP.
type QemuProvider struct {
	conf  QemuProviderConf
	mutex sync.Mutex

	// watchers holds all registered watchers for device lifecycle events.
	// The key is device name (without prefix), and the value is a slice
	// of channels that receive DeviceStatus updates.
	watchers map[string][]chan DeviceStatus

	// A map of devices created by SetupDevice (and not yet removed by TeardownDevice).
	// The key is device name (without prefix).
	devices map[string]*qemuDevice

	// A map of uplink and xconnect networks created by SetupDevice, used by at least
	// one device.
	// The key is network name (without prefix).
	networks map[string]*qemuNetwork
}

// QemuProviderConf : configuration for the QEMU provider.
type QemuProviderConf struct {
	CommonProviderConf
	ArtifactDir string
}

type qemuDevice struct {
	name string
	spec DeviceSpec

	args      []string
	cmd       *exec.Cmd
	pid       int
	exitCh    chan struct{}
	exitAcked bool
	taps      []qemuTap
	status    DeviceStatus

	artifactDir string
	tmpDir      string
	consoleLog  string
	consolePort uint16

	qmpSocket string
	qmpClient *qmpClient

	tpm swtpm
}

type qemuNetwork struct {
	name        string
	bridge      string
	isUplink    bool
	ipv6Enabled bool
	dir         string
	dnsmasqPid  int
	dnsmasqCmd  *exec.Cmd
	radvdPid    int
	radvdCmd    *exec.Cmd
}

type qemuTap struct {
	name     string
	guestMAC net.HardwareAddr
	network  string
}

type swtpm struct {
	stateDir string
	socket   string
	logFile  string
	pid      int
}

// NewQemuProvider creates a new QEMU provider instance.
func NewQemuProvider(conf QemuProviderConf) (*QemuProvider, error) {
	p := &QemuProvider{
		conf:     conf,
		watchers: make(map[string][]chan DeviceStatus),
		devices:  make(map[string]*qemuDevice),
		networks: make(map[string]*qemuNetwork),
	}
	return p, nil
}

// -------- QMP client --------------------------

// qmpClient is a QEMU QMP client.
//
// It manages a single connection with one reader goroutine that decodes all
// JSON messages. Synchronous command responses are routed to the caller, and
// asynchronous events are sent to the event channel. Commands and events are
// processed concurrently and safely.
//
// Usage:
//
//	c, _ := dialQMP(ctx, log, socket)
//	go func() {
//	    for evt := range c.Events() {
//	        handleEvent(evt)
//	    }
//	}()
//	err := c.Execute(ctx, "query-status", nil, &status)
type qmpClient struct {
	log *logrus.Entry

	conn net.Conn
	enc  *json.Encoder

	reqCh   chan *qmpRequest
	eventCh chan qmpEvent
	closeCh chan struct{}

	mu      sync.Mutex
	pending map[uint64]chan qmpResponse
	nextID  uint64
}

type qmpRequest struct {
	cmd  string
	args any
	resp chan qmpResponse
	id   uint64
}

type qmpResponse struct {
	ID        uint64          `json:"id,omitempty"`
	Return    json.RawMessage `json:"return,omitempty"`
	Error     *qmpError       `json:"error,omitempty"`
	Event     string          `json:"event,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	Timestamp *qmpTimestamp   `json:"timestamp,omitempty"`
}

type qmpError struct {
	Class string `json:"class"`
	Desc  string `json:"desc"`
}

type qmpTimestamp struct {
	Seconds      int64 `json:"seconds"`
	Microseconds int64 `json:"microseconds"`
}

// qmpEvent represents an asynchronous QMP event.
type qmpEvent struct {
	name      string
	data      json.RawMessage
	timestamp *qmpTimestamp
}

// dialQMP connects to a QEMU QMP socket and enables capabilities.
func dialQMP(ctx context.Context, log *logrus.Entry, socket string) (*qmpClient, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to QMP socket %q: %w", socket, err)
	}

	c := &qmpClient{
		log:     log,
		conn:    conn,
		enc:     json.NewEncoder(conn),
		reqCh:   make(chan *qmpRequest),
		eventCh: make(chan qmpEvent, 32),
		closeCh: make(chan struct{}),
		pending: make(map[uint64]chan qmpResponse),
	}

	dec := json.NewDecoder(conn)
	var greeting map[string]any
	if err := dec.Decode(&greeting); err != nil {
		conn.Close()
		return nil, err
	}

	go c.reader(dec)
	go c.writer()

	if err := c.execute(ctx, "qmp_capabilities", nil, nil); err != nil {
		conn.Close()
		return nil, err
	}

	return c, nil
}

// Execute sends a QMP command and waits for the response.
func (c *qmpClient) execute(ctx context.Context, cmd string, args any, out any) error {
	respCh := make(chan qmpResponse, 1)

	c.mu.Lock()
	id := c.nextID
	c.nextID++
	c.pending[id] = respCh
	c.mu.Unlock()

	select {
	case c.reqCh <- &qmpRequest{cmd: cmd, args: args, resp: respCh, id: id}:
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case r := <-respCh:
		if r.Error != nil {
			return fmt.Errorf("%s (%s)", r.Error.Desc, r.Error.Class)
		}
		if out != nil && len(r.Return) > 0 {
			return json.Unmarshal(r.Return, out)
		}
		return nil
	}
}

// events returns a channel of asynchronous QMP events.
func (c *qmpClient) events() <-chan qmpEvent {
	return c.eventCh
}

// Close shuts down the client and closes the connection.
func (c *qmpClient) close() error {
	close(c.closeCh)
	return c.conn.Close()
}

func (c *qmpClient) reader(dec *json.Decoder) {
	for {
		var r qmpResponse
		if err := dec.Decode(&r); err != nil {
			if err != io.EOF {
				c.log.Errorf("QMP decode error: %v", err)
			}
			c.shutdown(err)
			return
		}

		if r.Event != "" {
			select {
			case c.eventCh <- qmpEvent{name: r.Event, data: r.Data, timestamp: r.Timestamp}:
			default:
				// drop if consumer is slow
			}
			continue
		}

		c.mu.Lock()
		ch := c.pending[r.ID]
		delete(c.pending, r.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- r
			close(ch)
		}
	}
}

func (c *qmpClient) writer() {
	for {
		select {
		case req := <-c.reqCh:
			msg := map[string]any{"execute": req.cmd, "id": req.id}
			if req.args != nil {
				msg["arguments"] = req.args
			}
			if err := c.enc.Encode(msg); err != nil {
				c.mu.Lock()
				delete(c.pending, req.id)
				c.mu.Unlock()
				req.resp <- qmpResponse{Error: &qmpError{Class: "io", Desc: err.Error()}}
				close(req.resp)
			}
		case <-c.closeCh:
			return
		}
	}
}

func (c *qmpClient) shutdown(err error) {
	c.mu.Lock()
	for _, ch := range c.pending {
		ch <- qmpResponse{Error: &qmpError{Class: "io", Desc: err.Error()}}
		close(ch)
	}
	c.pending = nil
	c.mu.Unlock()
	close(c.eventCh)
}

// -------- DeviceProvider implementation --------

// Close releases all resources associated with the provider.
func (p *QemuProvider) Close() error {
	return nil
}

// GetSupportedDeviceArchs returns the list of CPU architectures supported by QEMU
// on this host. Since we use KVM acceleration and avoid emulation, this returns
// only the host's native architecture.
func (p *QemuProvider) GetSupportedDeviceArchs() ([]api.ArchType, error) {
	return archFromRuntime()
}

// SetupDevice creates a VM configuration and prepares network resources,
// but does not start the VM (powered-off state).
func (p *QemuProvider) SetupDevice(
	ctx context.Context, name string, spec DeviceSpec) error {
	log := logger.FromContext(ctx)
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if _, ok := p.devices[name]; ok {
		err := fmt.Errorf("device %q already exists", name)
		log.Error(err)
		return err
	}

	tmpDir := p.deviceTmpDir(name)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		err = fmt.Errorf("failed to create temporary directory %q for device %q: %w",
			tmpDir, name, err)
		log.Error(err)
		return err
	}

	artifactDir := p.deviceArtifactDir(name)
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		err = fmt.Errorf("failed to create artifact directory %q for device %q: %w",
			artifactDir, name, err)
		log.Error(err)
		return err
	}

	dev := &qemuDevice{
		name:        name,
		spec:        spec,
		artifactDir: artifactDir,
		tmpDir:      tmpDir,
		qmpSocket:   filepath.Join(tmpDir, "qmp.sock"),
		consoleLog:  filepath.Join(artifactDir, "console.log"),
	}

	// TPM (swtpm) configuration (powered-off)
	if spec.WithTPM {
		tpmDir := filepath.Join(tmpDir, "swtpm")
		if err := os.MkdirAll(tpmDir, 0o755); err != nil {
			err = fmt.Errorf("failed to create TPM state dir %q for device %q: %w",
				tpmDir, name, err)
			log.Error(err)
			return err
		}
		dev.tpm.stateDir = tpmDir
		dev.tpm.socket = filepath.Join(tpmDir, "swtpm.sock")
		dev.tpm.logFile = filepath.Join(artifactDir, "swtpm.log")
	}

	// Ensure that all networks are ready.
	for _, iface := range spec.NetworkInterfaces {
		var err error
		var network *qemuNetwork
		switch {
		case iface.Connection.Uplink != nil:
			uplink := iface.Connection.Uplink
			network, err = p.ensureUplinkNetwork(log, uplink.EnableIPv6)
			if err != nil {
				return err
			}

		case iface.Connection.XConnect != nil:
			xconnect := iface.Connection.XConnect
			prefixedNetName := xconnectNetworkName(
				name, iface.Name, xconnect.PeerDeviceName, xconnect.PeerInterfaceName)
			network, err = p.ensureXConnectNetwork(log, prefixedNetName)
			if err != nil {
				return err
			}

		default:
			err = fmt.Errorf("missing ConnectionSpec for interface %q in device %q",
				iface.Name, name)
			log.Error(err)
			return err
		}
		tap := generateTapName(name, iface.Name)
		if err = utils.CreateTap(tap); err != nil {
			err = fmt.Errorf("failed to create TAP %q for device %q: %w",
				tap, name, err)
			log.Error(err)
			return err
		}
		if err = utils.ConnectTapToBridge(network.bridge, tap); err != nil {
			err = fmt.Errorf("failed to attach TAP %q into the bridge %q: %w",
				tap, network.bridge, err)
			log.Error(err)
			return err
		}
		mac := iface.MACAddress
		if mac == nil || len(mac) == 0 {
			mac = utils.GenerateMAC(dev.name, iface.Name)
		}
		dev.taps = append(dev.taps, qemuTap{
			network:  network.name,
			name:     tap,
			guestMAC: mac,
		})
	}

	// Enable LACP forwarding on xconnect bridges.
	if err := enableLACPForwardingOnXConnectBridges(); err != nil {
		log.Warnf("Failed to enable LACP forwarding: %v", err)
	}

	// Allocate the console port now so buildArgs can embed it.
	consolePort, err := utils.FindUnusedPort(ipv4Loopback)
	if err != nil {
		log.Error(err)
		return err
	}
	dev.consolePort = consolePort
	dev.args = dev.buildArgs()
	log.Debugf("Device %q arguments: %s", name, dev.args)

	p.devices[name] = dev
	p.updateDeviceStatus(dev, DeviceStatusStopped)
	log.Infof("Device %q prepared in powered-off state", name)
	return nil
}

// TeardownDevice stops the device (if running) and removes all associated
// resources (TAP devices, config files, etc.).
func (p *QemuProvider) TeardownDevice(ctx context.Context, name string) error {
	log := logger.FromContext(ctx)
	p.mutex.Lock()
	defer p.mutex.Unlock()

	dev, ok := p.devices[name]
	if !ok {
		err := fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
		log.Error(err)
		return err
	}

	// Power-Off the device if it is running.
	if dev.cmd != nil {
		err := stopQemuProcess(ctx, dev.name, dev.pid, dev.qmpClient, dev.exitCh)
		if err != nil {
			return err
		}
	}

	if err := p.teardownStoppedDevice(log, dev); err != nil {
		return err
	}

	// Garbage-collect unused networks
	p.teardownUnusedNetworks(ctx, log)
	return nil
}

// PowerOnDevice starts a previously configured VM by launching the QEMU process.
func (p *QemuProvider) PowerOnDevice(ctx context.Context, name string) error {
	log := logger.FromContext(ctx)
	p.mutex.Lock()
	defer p.mutex.Unlock()

	dev, ok := p.devices[name]
	if !ok {
		err := fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
		log.Error(err)
		return err
	}
	if dev.status == DeviceStatusRunning {
		err := fmt.Errorf("failed to power-on device %q: already running", name)
		log.Error(err)
		return err
	}

	// Create QEMU command for the selected architecture.
	cmd := exec.Command("qemu-system-"+qemuArch(), dev.args...)

	// Redirect QEMU stdout to file.
	stdoutPath := filepath.Join(dev.artifactDir, "qemu-stdout")
	stdoutFile, err := os.OpenFile(stdoutPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open QEMU stdout file %q: %w", stdoutPath, err)
	}
	cmd.Stdout = stdoutFile

	// Redirect QEMU stderr to file.
	stderrPath := filepath.Join(dev.artifactDir, "qemu-stderr")
	stderrFile, err := os.OpenFile(stderrPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		_ = stdoutFile.Close()
		return fmt.Errorf("failed to open QEMU stderr file %q: %w", stderrPath, err)
	}
	cmd.Stderr = stderrFile

	// Start swtpm before launching QEMU
	if dev.spec.WithTPM {
		dev.tpm.pid, err = startSWTPM(dev.tpm.stateDir, dev.tpm.socket, dev.tpm.logFile)
		if err != nil {
			_ = stdoutFile.Close()
			_ = stderrFile.Close()
			return fmt.Errorf("failed to start swtpm for device %q: %w", name, err)
		}
	}

	// Start the Qemu process.
	if err := cmd.Start(); err != nil {
		_ = stdoutFile.Close()
		_ = stderrFile.Close()
		err = fmt.Errorf("failed to start qemu process for device %q: %w", name, err)
		log.Error(err)
		return err
	}

	dev.cmd = cmd
	dev.pid = cmd.Process.Pid
	p.updateDeviceStatus(dev, DeviceStatusRunning)

	// Signal when qemu process exits.
	exitCh := make(chan struct{})
	dev.exitCh = exitCh
	dev.exitAcked = false

	// Goroutine that waits for the QEMU process to exit.
	go func() {
		err := cmd.Wait()
		_ = stdoutFile.Close()
		_ = stderrFile.Close()
		close(exitCh)

		p.mutex.Lock()
		defer p.mutex.Unlock()
		if !dev.exitAcked {
			dev.cmd = nil
			dev.pid = 0
			if err == nil {
				log.Infof("Device %q exited normally, updating status to STOPPED",
					dev.name)
				p.updateDeviceStatus(dev, DeviceStatusStopped)
			} else {
				log.Warnf("Device %q exited with error: %v, updating status to CRASHED",
					dev.name, err)
				p.updateDeviceStatus(dev, DeviceStatusCrashed)
			}
			dev.exitAcked = true
		} else {
			log.Debugf("Device %q exit already acknowledged, skipping status update",
				dev.name)
		}
		if dev.spec.WithTPM {
			if err := stopSWTPM(dev.tpm.pid); err != nil {
				log.Warnf("failed to stop swtpm for device %q: %v", dev.name, err)
			}
			dev.tpm.pid = 0
		}
	}()

	// Connect to the QEMU Machine Protocol.
	const maxAttempts = 20
	const retryDelay = 1 * time.Second
	const dialTimeout = 3 * time.Second

	for i := 0; i < maxAttempts; i++ {
		select {
		case <-exitCh:
			err = fmt.Errorf(
				"device %q exited even before establishing connection to QMP", dev.name)
			log.Error(err)
			return err
		default:
		}
		dialCtx, cancelDialCtx := context.WithTimeout(ctx, dialTimeout)
		dev.qmpClient, err = dialQMP(dialCtx, log, dev.qmpSocket)
		cancelDialCtx()
		if err == nil {
			break
		}
		dev.qmpClient = nil
		if i > 5 {
			log.Debugf("Attempt %d: failed to connect QMP for device %q: %v",
				i+1, dev.name, err)
		}
		time.Sleep(retryDelay)
	}
	if err != nil {
		err = fmt.Errorf("could not connect to QMP for device %q after %d attempts: %v",
			dev.name, maxAttempts, err)
		log.Error(err)
		// Make sure we do leave the Qemu process running.
		if err := syscall.Kill(dev.pid, syscall.SIGKILL); err != nil {
			log.Warnf("Failed to send SIGKILL to device %q: %v", dev.name, err)
		}
		return err
	}

	// Goroutine for processing QMP events and updating device status watchers.
	go func() {
		outputPath := filepath.Join(dev.artifactDir, "qemu-events")
		outputFile, err := os.OpenFile(
			outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			log.Warnf("failed to create output file %s for QMP events: %v",
				outputPath, err)
			outputFile = nil
		} else {
			defer outputFile.Close()
		}

		for {
			eventCh := dev.qmpClient.events()
			select {
			case <-exitCh:
				log.Debugf("QMP event watcher exiting for device %q", dev.name)
				return

			case event, ok := <-eventCh:
				if !ok {
					log.Infof("QMP event channel was closed for device %q", dev.name)
					return
				}
				if outputFile != nil {
					ts := time.Now().UTC().Format(time.RFC3339Nano)
					data := ""
					if len(event.data) > 0 {
						data = string(event.data)
					}
					_, _ = fmt.Fprintf(outputFile, "%s EVENT=%q DATA=%q\n",
						ts, event.name, data)
				}

				switch event.name {
				case "STOP", "SHUTDOWN", "POWERDOWN":
					log.Infof("QMP event %q received for device %q, "+
						"updating status to STOPPED", event.name, dev.name)
					p.mutex.Lock()
					if !dev.exitAcked {
						dev.cmd = nil
						dev.pid = 0
						p.updateDeviceStatus(dev, DeviceStatusStopped)
						dev.exitAcked = true
					}
					p.mutex.Unlock()

				case "SUSPEND":
					log.Infof("QMP event %q received for device %q, "+
						"updating status to SUSPENDED", event.name, dev.name)
					p.mutex.Lock()
					p.updateDeviceStatus(dev, DeviceStatusSuspended)
					p.mutex.Unlock()

				case "RESUME":
					log.Infof("QMP event %q received for device %q, "+
						"updating status to RUNNING", event.name, dev.name)
					p.mutex.Lock()
					p.updateDeviceStatus(dev, DeviceStatusRunning)
					p.mutex.Unlock()
				}
			}
		}
	}()

	log.Infof("Device %q was powered ON", name)
	return nil
}

// PowerOffDevice performs a hard power-off by killing the QEMU process.
func (p *QemuProvider) PowerOffDevice(ctx context.Context, name string) error {
	log := logger.FromContext(ctx)
	p.mutex.Lock()
	dev, ok := p.devices[name]
	if !ok {
		p.mutex.Unlock()
		err := fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
		log.Error(err)
		return err
	}
	pid := dev.pid
	qmp := dev.qmpClient
	exitCh := dev.exitCh
	p.mutex.Unlock()

	if err := stopQemuProcess(ctx, name, pid, qmp, exitCh); err != nil {
		return err
	}
	log.Infof("Device %q was powered OFF", name)
	return nil
}

// ShutdownDevice performs a graceful shutdown via QMP/ACPI.
func (p *QemuProvider) ShutdownDevice(ctx context.Context, name string) error {
	log := logger.FromContext(ctx)

	p.mutex.Lock()
	dev, ok := p.devices[name]
	if !ok {
		p.mutex.Unlock()
		err := fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
		log.Error(err)
		return err
	}
	if dev.status != DeviceStatusRunning {
		p.mutex.Unlock()
		err := fmt.Errorf("device %q is not running", name)
		log.Error(err)
		return err
	}
	qmp := dev.qmpClient
	exitCh := dev.exitCh
	p.mutex.Unlock()

	// Send ACPI shutdown
	if err := qmp.execute(ctx, "system_powerdown", nil, nil); err != nil {
		err = fmt.Errorf("failed to send ACPI shutdown to %q: %w", name, err)
		log.Error(err)
		return err
	}

	log.Infof("ACPI shutdown requested for device %q", name)

	// Wait for QEMU process to exit
	select {
	case <-ctx.Done():
		return fmt.Errorf("shutdown of device %q timed out: %w", name, ctx.Err())
	case <-exitCh:
		log.Infof("Device %q shut down gracefully", name)
	}
	return nil
}

// RebootDevice performs a reboot via QMP.
func (p *QemuProvider) RebootDevice(ctx context.Context, name string) error {
	log := logger.FromContext(ctx)

	p.mutex.Lock()
	dev, ok := p.devices[name]
	if !ok {
		p.mutex.Unlock()
		err := fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
		log.Error(err)
		return err
	}
	if dev.status != DeviceStatusRunning {
		p.mutex.Unlock()
		err := fmt.Errorf("device %q is not running", name)
		log.Error(err)
		return err
	}
	qmp := dev.qmpClient
	p.mutex.Unlock()

	// Issue reset
	if err := qmp.execute(ctx, "system_reset", nil, nil); err != nil {
		err = fmt.Errorf("failed to reboot device %q via QMP: %w", name, err)
		log.Error(err)
		return err
	}

	log.Infof("Reboot requested for device %q", name)
	return nil
}

// GetDeviceConsoleOutput retrieves the console output from the console log file.
func (p *QemuProvider) GetDeviceConsoleOutput(
	ctx context.Context, name string) (string, error) {
	log := logger.FromContext(ctx)

	// Get path to console logfile (per device)
	p.mutex.Lock()
	dev, ok := p.devices[name]
	if !ok {
		p.mutex.Unlock()
		err := fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
		log.Error(err)
		return "", err
	}
	logfile := dev.consoleLog
	p.mutex.Unlock()

	if logfile == "" {
		err := fmt.Errorf("console log file not configured for device %q", name)
		log.Error(err)
		return "", err
	}
	data, err := os.ReadFile(logfile)
	if err != nil {
		err = fmt.Errorf("failed to read console log %q: %w", logfile, err)
		log.Error(err)
		return "", err
	}
	return string(data), nil
}

// AttachToDeviceConsole returns a stream attached to the device's serial console
// (via telnet socket or similar).
func (p *QemuProvider) AttachToDeviceConsole(ctx context.Context,
	name string) (stream io.ReadWriteCloser, echoed, telnet bool, err error) {
	log := logger.FromContext(ctx)
	// qemu's TCP serial echoes back the user input.
	echoed = true
	// Telnet protocol is enabled.
	telnet = true

	// Get TCP port for the device console
	p.mutex.Lock()
	dev, ok := p.devices[name]
	if !ok {
		p.mutex.Unlock()
		err = fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
		log.Error(err)
		return nil, echoed, telnet, err
	}
	port := dev.consolePort
	p.mutex.Unlock()

	if port == 0 {
		err = fmt.Errorf("console port not configured for device %q", name)
		log.Error(err)
		return nil, echoed, telnet, err
	}

	// Connect to the console.
	consoleAddr := net.JoinHostPort(ipv4Loopback.String(), strconv.Itoa(int(port)))
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", consoleAddr)
	if err != nil {
		err = fmt.Errorf("failed to connect to device %q console on port %d: %w",
			name, port, err)
		log.Error(err)
		return nil, echoed, telnet, err
	}
	return conn, echoed, telnet, nil
}

// GetDeviceStatus returns the current status of the device by checking
// the QEMU process and querying QMP for authoritative VM state.
func (p *QemuProvider) GetDeviceStatus(
	ctx context.Context, name string) (DeviceStatus, error) {
	log := logger.FromContext(ctx)

	p.mutex.Lock()
	dev, ok := p.devices[name]
	if !ok {
		p.mutex.Unlock()
		err := fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
		log.Error(err)
		return DeviceStatusUnknown, err
	}
	pid := dev.pid
	qmp := dev.qmpClient
	p.mutex.Unlock()

	// Step 1: If we have no PID, the device is definitely stopped
	if pid == 0 {
		return DeviceStatusStopped, nil
	}

	// Step 2: Check whether the QEMU process still exists
	if err := syscall.Kill(pid, 0); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			// QEMU process exited
			return DeviceStatusStopped, nil
		}
		err = fmt.Errorf("failed to probe qemu process for device %q: %w", name, err)
		log.Error(err)
		return DeviceStatusUnknown, err
	}

	// Step 3: Query QMP for the actual VM state
	var resp struct {
		Status string `json:"status"`
	}
	if err := qmp.execute(ctx, "query-status", nil, &resp); err != nil {
		log.Error(err)
		return DeviceStatusUnknown, err
	}

	// Step 4: Map QMP state to provider DeviceStatus
	switch resp.Status {
	case "running":
		return DeviceStatusRunning, nil
	case "paused", "prelaunch":
		return DeviceStatusSuspended, nil
	case "shutdown":
		return DeviceStatusStopped, nil
	default:
		log.Debugf("unknown QMP status %q for device %q", resp.Status, name)
		return DeviceStatusUnknown, nil
	}
}

// GetDeviceUplinkIPs returns all IP addresses assigned to the uplink interfaces
// by querying the dnsmasq DHCP leases file.
func (p *QemuProvider) GetDeviceUplinkIPs(
	ctx context.Context, name string) (ips []net.IP, err error) {
	log := logger.FromContext(ctx)
	p.mutex.Lock()
	defer p.mutex.Unlock()

	dev, ok := p.devices[name]
	if !ok {
		err = fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
		log.Error(err)
		return nil, err
	}

	for _, tap := range dev.taps {
		network := p.networks[tap.network]
		if network == nil {
			log.Warnf("failed to find network %q", tap.network)
			continue
		}
		if !network.isUplink {
			continue
		}
		leaseFilePath := filepath.Join(network.dir, "dnsmasq.leases")
		leasedIPs, err := getDnsmasqLeases(log, leaseFilePath, tap.guestMAC)
		if err != nil {
			log.Warnf("failed to get DHCP leases for MAC address %q: %v",
				tap.guestMAC.String(), err)
			continue
		}
		ips = append(ips, leasedIPs...)
	}
	return ips, nil
}

// WatchDeviceStatus returns a channel that receives status updates for a device.
// The first value sent is always the current status.
func (p *QemuProvider) WatchDeviceStatus(
	ctx context.Context, name string) <-chan DeviceStatus {
	ch := make(chan DeviceStatus, 10)

	// Add this channel to the list of watchers
	p.mutex.Lock()
	p.watchers[name] = append(p.watchers[name], ch)
	p.mutex.Unlock()

	go func() {
		defer func() {
			// Remove this watcher from the list and close the channel.
			// If teardownStoppedDevice already closed and removed it, skip the close
			// to avoid a double-close panic.
			p.mutex.Lock()
			defer p.mutex.Unlock()
			wlist := p.watchers[name]
			for i, c := range wlist {
				if c == ch {
					p.watchers[name] = append(wlist[:i], wlist[i+1:]...)
					close(ch)
					break
				}
			}
		}()

		// Send initial status
		st, err := p.GetDeviceStatus(ctx, name)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				ch <- DeviceStatusUnknown
			}
			return
		}
		ch <- st

		// Wait until context cancellation
		<-ctx.Done()
	}()

	return ch
}

// ListDevices returns the names of all devices created by this provider.
func (p *QemuProvider) ListDevices(ctx context.Context) ([]string, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	var devices []string
	for devName := range p.devices {
		devices = append(devices, devName)
	}
	return devices, nil
}

// TeardownAll removes all VMs and networks created by this provider.
func (p *QemuProvider) TeardownAll(ctx context.Context) error {
	log := logger.FromContext(ctx)
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, dev := range p.devices {
		// Power-Off the device if it is running.
		if dev.cmd != nil {
			err := stopQemuProcess(ctx, dev.name, dev.pid, dev.qmpClient, dev.exitCh)
			if err != nil {
				return err
			}
		}
		if err := p.teardownStoppedDevice(log, dev); err != nil {
			return err
		}
	}

	// Garbage-collect unused networks
	p.teardownUnusedNetworks(ctx, log)
	return nil
}

// ReconfigureDeviceDisks swaps the disk list of a stopped device in place.
// The swtpm state, UEFI NVRAM, console socket, and network taps are all
// preserved because the same qemuDevice entry is reused.
func (p *QemuProvider) ReconfigureDeviceDisks(
	ctx context.Context, name string, newDisks []DiskImage) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	log := logger.FromContext(ctx)

	dev, ok := p.devices[name]
	if !ok {
		return fmt.Errorf("device %q not found", name)
	}
	if dev.cmd != nil {
		return fmt.Errorf("device %q is running; stop it before reconfiguring disks",
			name)
	}

	dev.spec.Disks = newDisks
	dev.args = dev.buildArgs()
	log.Infof("Reconfigured disk list for device %q (%d disk(s))", name, len(newDisks))
	return nil
}

// --------- helpers ---------

// ensureUplinkNetwork creates or ensures a NAT network used for uplink connectivity
// exists. The network consists of:
//   - a Linux bridge with assigned IPv4/IPv6 addresses
//   - dnsmasq providing IPv4 DHCP and DNS forwarding
//   - optional radvd for IPv6 router advertisements
//   - iptables/ip6tables NAT rules for outbound connectivity
//
// QemuProvider.mutex must be held by the caller.
func (p *QemuProvider) ensureUplinkNetwork(
	log *logrus.Entry, ipv6Enabled bool) (*qemuNetwork, error) {

	// Resolve deterministic network + bridge names.
	prefixedNetName, brName := uplinkNetworkName(ipv6Enabled)
	netName := unprefixedName(prefixedNetName)

	// Fast path: network already exists.
	if network, ok := p.networks[netName]; ok {
		return network, nil
	}

	// Select IPv4 subnet depending on single-stack vs dual-stack mode.
	v4Subnet := p.conf.SDNUplinkIPv4OnlySubnet
	if ipv6Enabled {
		v4Subnet = p.conf.SDNUplinkIPv4DualStackSubnet
	}

	// Calculate bridge IPs and DHCP range.
	bridgeIPv4 := utils.GetFirstHostIP(v4Subnet)
	dhcpStart := utils.GetNextIP(bridgeIPv4)
	dhcpEnd := utils.GetLastHostIP(v4Subnet)

	brIPs := []*net.IPNet{
		utils.NewIPNet(bridgeIPv4, v4Subnet),
	}

	var bridgeIPv6 net.IP
	if ipv6Enabled && p.conf.SDNUplinkIPv6Subnet != nil {
		bridgeIPv6 = utils.GetFirstHostIP(p.conf.SDNUplinkIPv6Subnet)
		brIPs = append(brIPs,
			utils.NewIPNet(bridgeIPv6, p.conf.SDNUplinkIPv6Subnet))
	}

	// Create and bring up the Linux bridge with assigned IPs.
	if err := utils.CreateBridge(brName, brIPs, 0); err != nil {
		err = fmt.Errorf("failed to create bridge %q for network %q: %w",
			brName, netName, err)
		log.Error(err)
		return nil, err
	}

	// Create persistent directory for network state.
	dir := p.networkDir(netName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		err = fmt.Errorf("failed to create directory %q for network %q: %w",
			dir, netName, err)
		log.Error(err)
		return nil, err
	}

	// Paths for dnsmasq artifacts.
	confFile := filepath.Join(dir, "dnsmasq.conf")
	leaseFile := filepath.Join(dir, "dnsmasq.leases")
	logFile := filepath.Join(dir, "dnsmasq.log")

	// Build dnsmasq configuration (DHCP + DNS).
	var conf strings.Builder

	conf.WriteString(fmt.Sprintf(`
interface=%s
bind-interfaces
except-interface=lo

# DNS
port=53
domain-needed
bogus-priv
no-resolv
log-queries

# DHCPv4
dhcp-range=%s,%s,12h
dhcp-leasefile=%s
log-dhcp
log-facility=%s

# Advertise dnsmasq as DNS server for IPv4
dhcp-option=option:dns-server,%s

# Upstream IPv4 DNS
server=8.8.8.8
server=8.8.4.4
server=1.1.1.1
server=1.0.0.1
`,
		brName,
		dhcpStart.String(),
		dhcpEnd.String(),
		leaseFile,
		logFile,
		bridgeIPv4.String(),
	))

	// IPv6 DNS support.
	if ipv6Enabled && bridgeIPv6 != nil {
		conf.WriteString(`
# Upstream IPv6 DNS
server=2001:4860:4860::8888
server=2001:4860:4860::8844
server=2606:4700:4700::1111
server=2606:4700:4700::1001
`)
	}

	if err := os.WriteFile(confFile, []byte(conf.String()), 0o644); err != nil {
		err = fmt.Errorf("failed to write dnsmasq config file %q for network %q: %w",
			confFile, netName, err)
		log.Error(err)
		return nil, err
	}

	// Start dnsmasq in foreground mode.
	cmd := exec.Command("dnsmasq", "--no-daemon", "--conf-file="+confFile)
	if err := cmd.Start(); err != nil {
		err = fmt.Errorf("failed to start dnsmasq for network %q: %w", netName, err)
		log.Error(err)
		return nil, err
	}

	network := &qemuNetwork{
		name:        netName,
		bridge:      brName,
		isUplink:    true,
		ipv6Enabled: ipv6Enabled,
		dir:         dir,
		dnsmasqCmd:  cmd,
		dnsmasqPid:  cmd.Process.Pid,
	}

	// Configure and start radvd for IPv6 RA.
	if ipv6Enabled && p.conf.SDNUplinkIPv6Subnet != nil {
		radvdConf := filepath.Join(dir, "radvd.conf")
		radvdData := fmt.Sprintf(`
interface %s {
	AdvSendAdvert on;
	AdvDefaultLifetime 1800;
	AdvManagedFlag off;
	AdvOtherConfigFlag off;
	prefix %s {
		AdvOnLink on;
		AdvAutonomous on;
	};
	RDNSS %s {
		AdvRDNSSLifetime 600;
	};
};
`, brName, p.conf.SDNUplinkIPv6Subnet.String(), bridgeIPv6.String())

		if err := os.WriteFile(radvdConf, []byte(radvdData), 0o644); err != nil {
			err = fmt.Errorf("failed to write radvd config file %q for network %q: %w",
				radvdConf, netName, err)
			log.Error(err)
			return nil, err
		}

		// Even though we do not use radvd PID file, it must be a valid filepath.
		radvdPidFile := filepath.Join(dir, "radvd.pid")
		radvd := exec.Command("radvd", "-n", "-p", radvdPidFile, "-C", radvdConf)
		if err := radvd.Start(); err != nil {
			err = fmt.Errorf("failed to start radvd for network %q: %w", netName, err)
			log.Error(err)
			return nil, err
		}

		network.radvdCmd = radvd
		network.radvdPid = radvd.Process.Pid
	}

	// Enable forwarding.
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	if ipv6Enabled {
		_ = exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1").Run()
	}

	// Configure IPv4 NAT.
	if err := exec.Command(
		"iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", v4Subnet.String(), "-j", "MASQUERADE",
	).Run(); err != nil {
		err = fmt.Errorf("failed to configure IPv4 NAT for network %q: %v",
			netName, err)
		log.Error(err)
		return nil, err
	}

	// Configure IPv6 NAT (NAT66).
	if ipv6Enabled && p.conf.SDNUplinkIPv6Subnet != nil {
		if err := exec.Command(
			"ip6tables", "-t", "nat", "-A", "POSTROUTING",
			"-s", p.conf.SDNUplinkIPv6Subnet.String(), "-j", "MASQUERADE",
		).Run(); err != nil {
			err = fmt.Errorf("failed to configure IPv6 NAT for network %q: %v",
				netName, err)
			log.Error(err)
			return nil, err
		}
	}

	// Register network.
	p.networks[netName] = network
	log.Infof("Created uplink network %q", netName)

	return network, nil
}

// ensureXConnectNetwork creates or ensures a simple L2-only network used to interconnect
// VMs exists.
// QemuProvider.mutex must be held by the caller.
func (p *QemuProvider) ensureXConnectNetwork(
	log *logrus.Entry, prefixedName string) (*qemuNetwork, error) {

	// Resolve deterministic network + bridge names.
	netName := unprefixedName(prefixedName)
	brName := generateXConnectBridgeName(prefixedName)

	// Fast path: network already exists.
	if network, ok := p.networks[netName]; ok {
		return network, nil
	}

	// Create and bring up the Linux bridge.
	// Enable forwarding of link-local protocols so the xconnect bridge behaves
	// like a transparent cable.
	// Note: LACP (bit 2) cannot be set in the bridge-level group_fwd_mask
	// (kernel rejects BR_GROUPFWD_RESTRICTED). It is enabled separately via
	// the per-port IFLA_BRPORT_GROUP_FWD_MASK in enableLACPForwardingOnXConnectBridges.
	groupFwdMask := uint16(0x4008) // EAPOL + LLDP
	if err := utils.CreateBridge(brName, nil, groupFwdMask); err != nil {
		err = fmt.Errorf("failed to create bridge %q for network %q: %w",
			brName, netName, err)
		log.Error(err)
		return nil, err
	}

	network := &qemuNetwork{
		name:   netName,
		bridge: brName,
	}
	p.networks[netName] = network
	log.Infof("Created xconnect network %q", netName)
	return network, nil
}

// updateDeviceStatus updates the cached status of a device and notifies all
// registered watchers about the status change.
// Notifications are sent in a non-blocking manner; if a watcher channel is
// full, the update is dropped to avoid blocking the provider.
// QemuProvider.mutex must be held by the caller.
func (p *QemuProvider) updateDeviceStatus(device *qemuDevice, newStatus DeviceStatus) {
	device.status = newStatus
	for _, ch := range p.watchers[device.name] {
		select {
		case ch <- newStatus:
		default:
			// Drop the update if the watcher is not ready to receive.
		}
	}
}

// Cleanup all resources associated with a stopped device.
// QemuProvider.mutex should be in the locked state.
func (p *QemuProvider) teardownStoppedDevice(log *logrus.Entry, dev *qemuDevice) error {
	for _, tap := range dev.taps {
		if err := utils.DeleteTap(tap.name); err != nil {
			err = fmt.Errorf("failed to delete TAP of the device %q: %w", dev.name, err)
			log.Error(err)
			return err
		}
	}
	dev.taps = nil

	_ = os.RemoveAll(dev.tmpDir)
	// Close all watcher channels so callers blocked on WatchDeviceStatus unblock.
	for _, ch := range p.watchers[dev.name] {
		close(ch)
	}
	delete(p.watchers, dev.name)
	delete(p.devices, dev.name)
	log.Infof("Device %q was torn-down", dev.name)
	return nil
}

// teardownUnusedNetworks removes all networks that are not used by any qemu process.
// It stops DHCP/RA/DNS services, removes NAT rules, deletes bridges, and cleans up
// network state directories.
//
// QemuProvider.mutex should be in the locked state.
func (p *QemuProvider) teardownUnusedNetworks(ctx context.Context, log *logrus.Entry) {
	for name, network := range p.networks {
		// Skip networks still referenced by at least one device.
		if p.isNetworkInUse(name) {
			continue
		}

		// Stop dnsmasq (IPv4 DHCP server) if running.
		if network.dnsmasqCmd != nil && network.dnsmasqCmd.Process != nil {
			_ = network.dnsmasqCmd.Process.Signal(syscall.SIGTERM)

			done := make(chan struct{})
			go func() {
				_ = network.dnsmasqCmd.Wait()
				close(done)
			}()

			select {
			case <-ctx.Done():
				log.Errorf("failed to stop dnsmasq for network %q: %v", name, ctx.Err())
			case <-done:
			}

			network.dnsmasqCmd = nil
			network.dnsmasqPid = 0
		}

		// Stop radvd (IPv6 Router Advertisement Daemon) if running.
		if network.radvdCmd != nil && network.radvdCmd.Process != nil {
			_ = network.radvdCmd.Process.Signal(syscall.SIGTERM)

			done := make(chan struct{})
			go func() {
				_ = network.radvdCmd.Wait()
				close(done)
			}()

			select {
			case <-ctx.Done():
				log.Errorf("failed to stop radvd for network %q: %v", name, ctx.Err())
			case <-done:
			}

			network.radvdCmd = nil
			network.radvdPid = 0
		}

		// Remove NAT rules for uplink networks.
		if network.isUplink {
			// Remove IPv4 NAT (MASQUERADE) rule.
			subnet := p.conf.SDNUplinkIPv4OnlySubnet
			if network.ipv6Enabled {
				subnet = p.conf.SDNUplinkIPv4DualStackSubnet
			}

			if subnet != nil {
				if err := exec.Command(
					"iptables",
					"-t", "nat",
					"-D", "POSTROUTING",
					"-s", subnet.String(),
					"-j", "MASQUERADE",
				).Run(); err != nil {
					log.Warnf("failed to remove IPv4 NAT rule for network %q: %v",
						name, err)
				}
			}

			// Remove IPv6 NAT (NAT66) rule if applicable.
			if network.ipv6Enabled && p.conf.SDNUplinkIPv6Subnet != nil {
				if err := exec.Command(
					"ip6tables",
					"-t", "nat",
					"-D", "POSTROUTING",
					"-s", p.conf.SDNUplinkIPv6Subnet.String(),
					"-j", "MASQUERADE",
				).Run(); err != nil {
					log.Warnf("failed to remove IPv6 NAT rule for network %q: %v",
						name, err)
				}
			}
		}

		// Delete Linux bridge.
		if err := utils.DeleteBridge(network.bridge); err != nil {
			log.Errorf("failed to delete bridge %q for network %q: %v",
				network.bridge, network.name, err)
		}

		// Remove persistent network directory (leases, configs).
		if network.dir != "" {
			if err := os.RemoveAll(network.dir); err != nil {
				log.Warnf("failed to remove directory %q for network %q: %v",
					network.dir, network.name, err)
			}
		}

		// Drop network from provider state.
		delete(p.networks, name)
		log.Infof("Removed network %q", name)
	}
}

// isNetworkInUse checks if any qemu process still uses the given network.
// QemuProvider.mutex should be in the locked state.
func (p *QemuProvider) isNetworkInUse(netName string) bool {
	for _, dev := range p.devices {
		for _, tap := range dev.taps {
			if tap.network == netName {
				return true
			}
		}
	}
	return false
}

func qemuArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return runtime.GOARCH
	}
}

// buildArgs assembles the full QEMU command-line argument list from the
// current device spec. It must be called after dev.consolePort is set.
func (dev *qemuDevice) buildArgs() []string {
	args := []string{
		"-enable-kvm",
		"-machine", "q35",
		"-cpu", "host",
		"-smp", fmt.Sprintf("%d", dev.spec.CPUs),
		"-m", fmt.Sprintf("%d", dev.spec.MemoryBytes>>20),
		"-nographic",
	}

	if dev.spec.SerialNumber != "" {
		args = append(args,
			"-smbios", fmt.Sprintf("type=1,serial=%s", dev.spec.SerialNumber),
		)
	}

	if dev.spec.WithTPM {
		tpmDev := "tpm-tis"
		if qemuArch() == "arm64" {
			tpmDev = "tpm-tis-device"
		}
		args = append(args,
			"-chardev", fmt.Sprintf("socket,id=chrtpm,path=%s", dev.tpm.socket),
			"-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
			"-device", fmt.Sprintf("%s,tpmdev=tpm0", tpmDev),
		)
	}

	for _, disk := range dev.spec.Disks {
		format := "qcow2"
		if disk.Format == DiskImageFormatRaw {
			format = "raw"
		}
		args = append(args, "-drive",
			fmt.Sprintf("file=%s,if=virtio,format=%s", disk.Path, format))
	}

	if dev.spec.UEFIFirmwareDirPath != "" {
		code := filepath.Join(dev.spec.UEFIFirmwareDirPath, "OVMF_CODE.fd")
		vars := filepath.Join(dev.spec.UEFIFirmwareDirPath, "OVMF_VARS.fd")
		args = append(args,
			"-drive", fmt.Sprintf("if=pflash,format=raw,readonly=on,file=%s", code),
			"-drive", fmt.Sprintf("if=pflash,format=raw,file=%s", vars),
		)
	}

	for i, tap := range dev.taps {
		args = append(args,
			"-netdev", fmt.Sprintf(
				"tap,id=net%d,ifname=%s,script=no,downscript=no", i, tap.name),
			"-device", fmt.Sprintf(
				"virtio-net-pci,netdev=net%d,mac=%s,speed=1000,duplex=full",
				i, tap.guestMAC.String()),
		)
	}

	args = append(args,
		"-chardev", fmt.Sprintf(
			"socket,id=char0,host=127.0.0.1,port=%d,server=on,wait=off,telnet=on,"+
				"logfile=%s,logappend=on", dev.consolePort, dev.consoleLog,
		),
		"-serial", "chardev:char0",
	)

	args = append(args,
		"-qmp", "unix:"+dev.qmpSocket+",server,nowait",
	)
	return args
}

func (p *QemuProvider) deviceArtifactDir(name string) string {
	if p.conf.ArtifactDir == "" {
		return p.deviceTmpDir(name)
	}
	return filepath.Join(p.conf.ArtifactDir, constants.QemuArtifactsDirname, name)
}

func (p *QemuProvider) deviceTmpDir(name string) string {
	return filepath.Join("/var/run", constants.QemuArtifactsDirname, name)
}

func (p *QemuProvider) networkDir(name string) string {
	return filepath.Join("/var/run", "evetest-qemu-networks", name)
}

// Stop the QEMU process gracefully, falling back to forceful termination.
func stopQemuProcess(ctx context.Context, devName string,
	pid int, qmp *qmpClient, exitCh <-chan struct{}) error {
	log := logger.FromContext(ctx)

	if pid == 0 {
		err := fmt.Errorf("failed to power-OFF device %q: qemu process is not running",
			devName)
		log.Error(err)
		return err
	}

	if qmp != nil {
		if err := qmp.close(); err != nil {
			log.Warnf("Failed to close QMP client for device %q: %v", devName, err)
		}
	}

	// Attempt graceful shutdown first (SIGTERM).
	log.Infof("Sending SIGTERM to QEMU process for device %q (pid=%d)",
		devName, pid)

	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		log.Warnf("Failed to send SIGTERM to device %q: %v", devName, err)
	}

	select {
	case <-ctx.Done():
		log.Warnf("Graceful shutdown (SIGTERM) for device %q failed (%v), forcing kill",
			devName, ctx.Err())

	case <-exitCh:
		log.Infof("Device %q shut down gracefully", devName)
		return nil
	}

	// Force kill (SIGKILL).
	log.Infof("Sending SIGKILL to QEMU process for device %q (pid=%d)",
		devName, pid)

	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		err = fmt.Errorf("failed to SIGKILL device %q: %w", devName, err)
		log.Error(err)
		return err
	}

	// Always wait after SIGKILL to reap the process.
	<-exitCh
	log.Infof("Device %q shut down forcefully", devName)
	return nil
}

// getDnsmasqLeases parses a dnsmasq leases file and returns all IP addresses
// currently leased to the given MAC address.
//
// dnsmasq lease file format:
//
//	<expiry> <mac> <ip> <hostname> <client-id>
func getDnsmasqLeases(log *logrus.Entry, leaseFilePath string,
	mac net.HardwareAddr) ([]net.IP, error) {

	f, err := os.Open(leaseFilePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	wantMAC := strings.ToLower(mac.String())
	var ips []net.IP

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		leaseMAC := strings.ToLower(fields[1])
		if leaseMAC != wantMAC {
			continue
		}
		ip := net.ParseIP(fields[2])
		if ip == nil {
			log.Warnf("invalid IP address in dnsmasq lease: %q", fields[2])
			continue
		}
		ips = append(ips, ip)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ips, nil
}

// startSWTPM starts a swtpm process in the given stateDir and socket path.
// Returns the PID of the swtpm process, so it can be stopped later.
func startSWTPM(stateDir, sockPath, logFile string) (pid int, err error) {
	args := []string{
		"socket",
		"--tpmstate", "dir=" + stateDir,
		"--ctrl", "type=unixio,path=" + sockPath,
		"--log", "level=20",
		"--tpm2",
	}

	cmd := exec.Command("swtpm", args...)

	// Redirect stdout/stderr to log file
	logF, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 0, fmt.Errorf("failed to open swtpm log file %q: %w", logFile, err)
	}
	cmd.Stdout = logF
	cmd.Stderr = logF

	if err := cmd.Start(); err != nil {
		_ = logF.Close()
		return 0, fmt.Errorf("failed to start swtpm: %w", err)
	}

	// Let swtpm run in background, close log file when it exits
	go func() {
		_ = cmd.Wait()
		_ = logF.Close()
	}()
	return cmd.Process.Pid, nil
}

// stopSWTPM stops a swtpm process by PID.
func stopSWTPM(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find swtpm process %d: %w", pid, err)
	}

	// Try graceful termination
	if err := proc.Signal(os.Interrupt); err != nil {
		// fallback to kill if interrupt fails
		_ = proc.Kill()
	}
	return nil
}
