// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	evecerts "github.com/lf-edge/eve-api/go/certs"
	eveconfig "github.com/lf-edge/eve-api/go/config"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	evelogs "github.com/lf-edge/eve-api/go/logs"
	evemetrics "github.com/lf-edge/eve-api/go/metrics"
	"github.com/lf-edge/eve/evetest/logger"
	"github.com/lf-edge/eve/evetest/utils"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// AdamStateType represents a lifecycle state of the Adam controller.
type AdamStateType int

const (
	// AdamStateStarting indicates that Adam startup has begun
	// (process not yet running).
	AdamStateStarting AdamStateType = iota
	// AdamStateRunning indicates that the Adam process has been
	// successfully started and is running.
	AdamStateRunning
	// AdamStateStopping indicates that a graceful shutdown
	// has been initiated.
	AdamStateStopping
	// AdamStateStopped indicates that Adam exited cleanly
	// after a requested shutdown.
	AdamStateStopped
	// AdamStateCrashed indicates that Adam exited unexpectedly
	// or failed during startup.
	AdamStateCrashed
)

const (
	streamHeader = "X-Stream"
	streamValue  = "true"
)

// AdamClient manages the lifecycle of an Adam controller instance.
// It is responsible for generating TLS assets, starting the Adam process,
// monitoring it for unexpected exits, and shutting it down cleanly.
type AdamClient struct {
	log        *logrus.Entry
	runDir     string
	hostname   string
	listenIPs  []net.IP
	listenPort uint16

	// certificates and their corresponding private keys
	caCert      *x509.Certificate
	caKey       *rsa.PrivateKey
	tlsCert     *x509.Certificate
	tlsKey      *ecdsa.PrivateKey
	signingCert *x509.Certificate
	signingKey  *ecdsa.PrivateKey
	ecdhCert    *x509.Certificate
	ecdhKey     *ecdsa.PrivateKey

	adamPid int
	adamCmd *exec.Cmd
	exitCh  chan struct{}
	exitErr error

	// statusCh is an optional channel used to publish lifecycle events.
	// Sends are non-blocking; events may be dropped if the channel is full.
	statusCh chan<- AdamState

	// Mutex protecting the maps below.
	// Note that we never run methods targeting the same device in parallel.
	// But we can run parallel methods for the same onboarding certificate,
	// just different serials.
	mutex sync.Mutex

	// knownDevices tracks devices registered or onboarded via this client
	knownDevices map[uuid.UUID]struct{}

	// onboardSerials maps onboarding cert fingerprint → set of serials
	onboardSerials map[string]map[string]struct{}
}

// AdamState is a lifecycle notification emitted by AdamClient.
type AdamState struct {
	// Type is the lifecycle state.
	Type AdamStateType
	// Err is set if the state transition was caused by an error.
	// It is only meaningful for AdamStateCrashed.
	Err error
}

// deviceCertPayload is used for sending and also receiving device certificate,
// onboard certificate and serial to/from Adam in JSON.
type deviceCertPayload struct {
	Cert    []byte `json:"cert"`    // PEM-encoded certificate
	Onboard []byte `json:"onboard"` // PEM-encoded onboarding certificate
	Serial  string `json:"serial"`  // Device serial number
}

// onboardCertPayload is used for sending an onboard cert and serials to Adam in JSON.
type onboardCertPayload struct {
	Cert   []byte `json:"cert"`   // PEM-encoded onboarding certificate
	Serial string `json:"serial"` // Device serial number
}

// ReqEvent represents a single HTTP request issued by an EVE device
// towards the Adam controller. It is used for request logging/auditing
// and captures timing, identity, network origin, and request metadata.
type ReqEvent struct {
	Timestamp time.Time `json:"timestamp"`
	UUID      uuid.UUID `json:"uuid,omitempty"`
	ClientIP  string    `json:"client-ip"`
	Forwarded string    `json:"forwarded,omitempty"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
}

// certs encapsulated device certs received from Adam.
type certs struct {
	Certs []*evecerts.ZCert `json:"certs,omitempty"`
}

// InfoMsgIterator iterates over device informational messages (ZInfoMsg).
// Iterate is called for each message that passes the match filter.
// Returning stop=true signals that no further messages are needed and
// iteration should stop cleanly. Returning a non-nil error aborts iteration
// and propagates the error to the caller.
type InfoMsgIterator interface {
	Iterate(msg *eveinfo.ZInfoMsg) (stop bool, err error)
}

// MetricMsgIterator iterates over device metric messages (ZMetricMsg).
// Iterate is called for each message that passes the match filter.
// Returning stop=true signals that no further messages are needed and
// iteration should stop cleanly. Returning a non-nil error aborts iteration
// and propagates the error to the caller.
type MetricMsgIterator interface {
	Iterate(msg *evemetrics.ZMetricMsg) (stop bool, err error)
}

// NewAdamClient creates a new AdamClient.
// The caller is responsible for providing a CA certificate and key used
// to sign all Adam server certificates.
// If statusCh is non-nil, Adam lifecycle events are published to it
// using non-blocking sends.
func NewAdamClient(log *logrus.Entry,
	runDir string, hostname string, listenIPs []net.IP, listenPort uint16,
	caCert *x509.Certificate, caKey *rsa.PrivateKey,
	statusCh chan<- AdamState,
) *AdamClient {
	return &AdamClient{
		log:            log,
		runDir:         runDir,
		hostname:       hostname,
		listenIPs:      listenIPs,
		listenPort:     listenPort,
		caCert:         caCert,
		caKey:          caKey,
		statusCh:       statusCh,
		knownDevices:   make(map[uuid.UUID]struct{}),
		onboardSerials: make(map[string]map[string]struct{}),
	}
}

// Start generates TLS certificates and launches the Adam controller.
// If Adam exits unexpectedly, the error is reported via the internal wait channel.
func (ac *AdamClient) Start() error {
	ac.publish(AdamStateStarting, nil)

	certDir, err := ac.generateCerts()
	if err != nil {
		err = fmt.Errorf("failed to generate certificates for Adam: %w", err)
		ac.publish(AdamStateCrashed, err)
		return err
	}

	dbDir := filepath.Join(ac.runDir, "adam-db")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		err = fmt.Errorf("failed to create Adam DB directory: %w", err)
		ac.publish(AdamStateCrashed, err)
		return err
	}

	cfgDir := filepath.Join(ac.runDir, "adam-cfg")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		err = fmt.Errorf("failed to create Adam config directory: %w", err)
		ac.publish(AdamStateCrashed, err)
		return err
	}

	var args []string
	args = append(args,
		"server",
		"--port", strconv.Itoa(int(ac.listenPort)))
	for _, listenIP := range ac.listenIPs {
		args = append(args,
			"--ip", listenIP.String())
	}
	args = append(args,
		"--db-url", dbDir,
		"--conf-dir", cfgDir,
		"--server-cert", filepath.Join(certDir, "tls.pem"),
		"--server-key", filepath.Join(certDir, "tls-key.pem"),
		"--signing-cert", filepath.Join(certDir, "signing.pem"),
		"--signing-key", filepath.Join(certDir, "signing-key.pem"),
		"--encrypt-cert", filepath.Join(certDir, "ecdh.pem"),
		"--encrypt-key", filepath.Join(certDir, "ecdh-key.pem"))
	cmd := exec.Command("adam", args...)

	// Redirect Adam stdout+stderr to file.
	outputPath := filepath.Join(ac.runDir, "adam-stdout")
	outputFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		err = fmt.Errorf("failed to open Adam output file %q: %w", outputPath, err)
		ac.publish(AdamStateCrashed, err)
		return err
	}
	cmd.Stdout = outputFile
	cmd.Stderr = outputFile

	// Start the adam process.
	if err = cmd.Start(); err != nil {
		err = fmt.Errorf("failed to start Adam process: %w", err)
		ac.publish(AdamStateCrashed, err)
		return fmt.Errorf("start adam: %w", err)
	}
	ac.adamCmd = cmd
	ac.adamPid = cmd.Process.Pid
	ac.log.Infof("Adam process started and listening on IPs:%v, port:%d",
		ac.listenIPs, ac.listenPort)
	ac.publish(AdamStateRunning, nil)

	// Signal when qemu process exits.
	ac.exitCh = make(chan struct{})
	go func() {
		err := cmd.Wait()
		_ = outputFile.Close()
		ac.exitErr = err
		close(ac.exitCh)
		if err != nil {
			ac.log.Errorf("Adam process crashed: %v", err)
			ac.publish(AdamStateCrashed, err)
		} else {
			ac.log.Info("Adam stopped")
			ac.publish(AdamStateStopped, nil)
		}
	}()
	return nil
}

// Stop terminates the Adam controller process and waits for it to exit.
func (ac *AdamClient) Stop() error {
	if ac.adamCmd == nil || ac.adamCmd.Process == nil {
		return nil
	}

	ac.publish(AdamStateStopping, nil)
	ac.log.Info("Stopping Adam")

	if err := ac.adamCmd.Process.Signal(syscall.SIGTERM); err != nil {
		err = fmt.Errorf("failed to send SIGTERM to Adam: %v", err)
		ac.publish(AdamStateCrashed, err)
		return err
	}

	select {
	case <-time.After(10 * time.Second):
		ac.log.Warn("Adam did not exit, killing")
		_ = ac.adamCmd.Process.Kill()
	case <-ac.exitCh:
	}
	ac.adamCmd = nil
	ac.adamPid = 0
	return nil
}

func (ac *AdamClient) httpClient() *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(ac.caCert)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
		},
	}
	return &http.Client{Transport: tr}
}

func (ac *AdamClient) adminURL(pathSuffix string) string {
	return fmt.Sprintf("https://%s:%d/admin/%s",
		ac.listenIPs[0].String(), ac.listenPort, pathSuffix)
}

func (ac *AdamClient) checkAdamRunning() error {
	select {
	case <-ac.exitCh:
		if ac.exitErr != nil {
			return fmt.Errorf("adam crashed: %v", ac.exitErr)
		}
		return errors.New("adam was stopped")
	default:
	}
	return nil
}

// openStream issues the streaming GET to the given Adam URL and returns once
// the server has accepted the connection (HTTP 200). The caller owns the
// returned response and must close its body.
func (ac *AdamClient) openStream(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GET %s request: %w", url, err)
	}
	req.Header.Set(streamHeader, streamValue)

	resp, err := ac.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s failed: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected HTTP status %s from %s", resp.Status, url)
	}
	return resp, nil
}

// GetSigningCertAndKey returns certificate+key used by the controller to sign payload
// send to a device wrapped inside AuthContainer.
func (ac *AdamClient) GetSigningCertAndKey() (*x509.Certificate, *ecdsa.PrivateKey) {
	return ac.signingCert, ac.signingKey
}

// GetECDHCertAndKey returns certificate+key used by the controller for object-level
// encryption (e.g., for WiFi password).
func (ac *AdamClient) GetECDHCertAndKey() (*x509.Certificate, *ecdsa.PrivateKey) {
	return ac.ecdhCert, ac.ecdhKey
}

// RegisterDevice directly registers a device certificate with Adam,
// allowing the device to skip onboarding and immediately authenticate.
func (ac *AdamClient) RegisterDevice(
	ctx context.Context, devCert *x509.Certificate) (uuid.UUID, error) {
	if err := ac.checkAdamRunning(); err != nil {
		return uuid.Nil, err
	}
	if devCert == nil {
		return uuid.Nil, errors.New("device certificate is nil")
	}

	cn := "<unknown>"
	if devCert.Subject.CommonName != "" {
		cn = devCert.Subject.CommonName
	}

	body, err := json.Marshal(deviceCertPayload{Cert: utils.CertToPEM(devCert)})
	if err != nil {
		err = fmt.Errorf(
			"failed to marshal device certificate (cert CN=%q) into JSON: %w", cn, err)
		return uuid.Nil, err
	}

	url := ac.adminURL("device")
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		err = fmt.Errorf("failed to create POST %s (cert CN=%q) request: %w",
			url, cn, err)
		return uuid.Nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := ac.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		err = fmt.Errorf("POST %s (cert CN=%q) failed: %w", url, cn, err)
		return uuid.Nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		err = fmt.Errorf("unexpected status from POST %s (cert CN=%q): %d",
			url, cn, resp.StatusCode)
		return uuid.Nil, err
	}

	devUUID, found, err := ac.findDeviceByCert(ctx, client, devCert)
	if err != nil {
		return uuid.Nil, err
	}
	if !found {
		err = fmt.Errorf("newly registered device (cert CN=%q) was not found", cn)
		return uuid.Nil, err
	}

	ac.mutex.Lock()
	ac.knownDevices[devUUID] = struct{}{}
	ac.mutex.Unlock()
	ac.log.Infof("Registered device UUID %q (cert CN=%q) with Adam controller",
		devUUID, cn)
	return devUUID, nil
}

// OnboardDevice installs a trusted onboarding certificate and waits
// until the device with the given serial appears in Adam.
func (ac *AdamClient) OnboardDevice(ctx context.Context,
	onboardCert *x509.Certificate, devSerial string) (uuid.UUID, error) {
	if err := ac.checkAdamRunning(); err != nil {
		return uuid.Nil, err
	}
	if onboardCert == nil {
		return uuid.Nil, errors.New("onboardCert is nil")
	}
	if devSerial == "" {
		return uuid.Nil, errors.New("device serial is empty")
	}

	fp := certFingerprint(onboardCert)
	cn := "<unknown>"
	if onboardCert.Subject.CommonName != "" {
		cn = onboardCert.Subject.CommonName
	}

	// Multiple devices may be onboarded in parallel using the same onboarding
	// certificate but different serial numbers. Adam expects the POST /onboard
	// request to always contain the complete set of serials associated with a
	// given onboarding certificate.
	//
	// Therefore, we must atomically:
	//   1) update the in-memory serial set for this certificate, and
	//   2) issue the corresponding onboarding HTTP request.
	//
	// Without this lock, concurrent goroutines could interleave such that a later
	// request is sent with an incomplete serial set, effectively reverting a
	// previously registered serial in Adam.
	ac.mutex.Lock()
	serials := ac.onboardSerials[fp]
	if serials == nil {
		serials = make(map[string]struct{})
		ac.onboardSerials[fp] = serials
	}
	serials[devSerial] = struct{}{}

	var serialList []string
	for s := range serials {
		serialList = append(serialList, s)
	}

	payload := onboardCertPayload{
		Cert:   utils.CertToPEM(onboardCert),
		Serial: strings.Join(serialList, ","),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		ac.mutex.Unlock()
		err = fmt.Errorf(
			"failed to marshal onboard certificate (cert CN=%q) + serials into JSON: %w",
			cn, err)
		return uuid.Nil, err
	}

	url := ac.adminURL("onboard")
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		ac.mutex.Unlock()
		err = fmt.Errorf("failed to create POST %s (cert CN=%q) request: %w",
			url, cn, err)
		return uuid.Nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := ac.httpClient()
	resp, err := client.Do(req)
	ac.mutex.Unlock()
	if err != nil {
		err = fmt.Errorf("POST %s (cert CN=%q) failed: %w", url, cn, err)
		return uuid.Nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		err = fmt.Errorf("unexpected status from POST %s (cert CN=%q): %d",
			url, cn, resp.StatusCode)
		return uuid.Nil, err
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return uuid.Nil, ctx.Err()
		case <-ticker.C:
			devUUID, found, err := ac.findDeviceByOnboard(ctx, client, onboardCert, devSerial)
			if err == nil && found {
				ac.mutex.Lock()
				ac.knownDevices[devUUID] = struct{}{}
				ac.mutex.Unlock()
				ac.log.Infof(
					"Device UUID %q (onboard cert CN=%q) onboarded into Adam controller",
					devUUID, cn)
				return devUUID, nil
			}
			ac.log.Infof("Waiting for device (onboard cert CN=%q) to onboard...", cn)
		case <-ac.exitCh:
			if err := ac.checkAdamRunning(); err != nil {
				return uuid.Nil, err
			}
		}
	}
}

// RemoveDevice deletes a device from Adam.
func (ac *AdamClient) RemoveDevice(ctx context.Context, devUUID uuid.UUID) error {
	if err := ac.checkAdamRunning(); err != nil {
		return err
	}

	ac.mutex.Lock()
	_, known := ac.knownDevices[devUUID]
	ac.mutex.Unlock()
	if !known {
		return fmt.Errorf("unknown device UUID %q", devUUID)
	}

	url := ac.adminURL("device/" + devUUID.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		err = fmt.Errorf("failed to create DELETE %s request: %w",
			url, err)
		return err
	}

	client := ac.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		err = fmt.Errorf("DELETE %s failed: %w", url, err)
		return err
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status from DELETE %s: %d", url, resp.StatusCode)
		return err
	}

	ac.mutex.Lock()
	delete(ac.knownDevices, devUUID)
	ac.mutex.Unlock()
	return nil
}

// GetDeviceECDHCert retrieves the device's ECDH exchange certificate used to derive
// a shared symmetric key for encrypting and decrypting sensitive configuration data.
// It returns (nil, nil) if the device exists but has not yet published an ECDH
// certificate.
func (ac *AdamClient) GetDeviceECDHCert(ctx context.Context,
	devUUID uuid.UUID) (*x509.Certificate, error) {
	if err := ac.checkAdamRunning(); err != nil {
		return nil, err
	}

	ac.mutex.Lock()
	_, known := ac.knownDevices[devUUID]
	ac.mutex.Unlock()
	if !known {
		return nil, fmt.Errorf("unknown device UUID %q", devUUID)
	}

	url := ac.adminURL("device/" + devUUID.String() + "/certs")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		err = fmt.Errorf("failed to create GET %s request: %w", url, err)
		return nil, err
	}

	client := ac.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		err = fmt.Errorf("GET %s failed: %w", url, err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status from GET %s: %d", url, resp.StatusCode)
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("failed to read GET %s response: %w", url, err)
		return nil, err
	}

	devCerts := &certs{}
	if err := json.Unmarshal(body, devCerts); err != nil {
		return nil, fmt.Errorf("failed to unmarshal device certificates: %w", err)
	}

	var devCert []byte
	for _, c := range devCerts.Certs {
		if c.Type == evecerts.ZCertType_CERT_TYPE_DEVICE_ECDH_EXCHANGE {
			devCert = c.Cert
		}
	}
	if len(devCert) == 0 {
		return nil, nil
	}

	block, _ := pem.Decode(devCert)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM block")
	}
	ecdhCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid x509 certificate: %w", err)
	}
	return ecdhCert, nil
}

// ApplyDeviceConfig uploads the current configuration for a device.
func (ac *AdamClient) ApplyDeviceConfig(ctx context.Context, devUUID uuid.UUID,
	config *eveconfig.EdgeDevConfig) error {
	if err := ac.checkAdamRunning(); err != nil {
		return err
	}

	ac.mutex.Lock()
	_, known := ac.knownDevices[devUUID]
	ac.mutex.Unlock()
	if !known {
		return fmt.Errorf("unknown device UUID %q", devUUID)
	}

	body, err := proto.Marshal(config)
	if err != nil {
		err = fmt.Errorf("failed to marshal device configuration: %w", err)
		return err
	}

	url := ac.adminURL("device/" + devUUID.String() + "/config")
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		err = fmt.Errorf("failed to create PUT %s request: %w",
			url, err)
		return err
	}
	req.Header.Set("Content-Type", "application/x-proto-binary")

	client := ac.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		err = fmt.Errorf("PUT %s failed: %w", url, err)
		return err
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status from PUT %s: %d", url, resp.StatusCode)
		return err
	}
	return nil
}

// WaitUntilDevRequest blocks until Adam observes an API request originating
// from the specified device that matches the given URL suffix.
//
// It establishes a streaming watch for device-originated API requests and
// returns when a matching request is observed or when ctx is canceled.
func (ac *AdamClient) WaitUntilDevRequest(
	ctx context.Context, devUUID uuid.UUID, urlSuffix string) error {

	startTime := time.Now()

	ch := make(chan *ReqEvent, 10)
	unsubscribe, err := ac.SubscribeToDeviceRequests(devUUID, ch)
	if err != nil {
		return err
	}
	defer unsubscribe()

	logTicker := time.NewTicker(10 * time.Second)
	defer logTicker.Stop()

	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return fmt.Errorf("request watcher stopped unexpectedly")
			}

			// Ignore events older than start time.
			if event.Timestamp.Before(startTime) {
				continue
			}

			if strings.HasSuffix(event.URL, urlSuffix) {
				ac.log.Debugf(
					"Observed device request %s %s at %s",
					event.Method, event.URL,
					event.Timestamp.Format(time.RFC3339),
				)
				return nil
			}

		case <-logTicker.C:
			ac.log.Debugf(
				"Waiting for device %q to perform request with URL suffix %q...",
				devUUID, urlSuffix,
			)

		case <-ctx.Done():
			return ctx.Err()

		case <-ac.exitCh:
			if err := ac.checkAdamRunning(); err != nil {
				return err
			}
		}
	}
}

// SubscribeToDeviceRequests registers a new subscriber for HTTP request events
// issued by the specified device towards the Adam controller.
//
// The streaming connection is opened synchronously: by the time this method
// returns, Adam has accepted the request and any subsequent events for the
// device will be delivered to the provided channel. On transient failures
// after the initial connection, a background goroutine reconnects with a
// fixed retry delay.
//
// The caller owns the provided channel and must ensure it is being drained.
// The channel will be closed automatically once the subscription is stopped.
//
// The returned unsubscribe function stops the background streaming goroutine,
// waits for it to exit, and guarantees that no more events will be sent
// to the channel after it returns. The function is idempotent and safe to call
// multiple times.
func (ac *AdamClient) SubscribeToDeviceRequests(
	devUUID uuid.UUID, channel chan<- *ReqEvent) (unsubscribe func(), err error) {
	const retryDelay = 3 * time.Second

	if err = ac.checkAdamRunning(); err != nil {
		return nil, err
	}

	// Verify device is known.
	ac.mutex.Lock()
	_, known := ac.knownDevices[devUUID]
	ac.mutex.Unlock()
	if !known {
		return nil, fmt.Errorf("unknown device UUID %q", devUUID)
	}

	streamCtx, cancel := context.WithCancel(context.Background())
	url := ac.adminURL("device/" + devUUID.String() + "/requests")

	resp, err := ac.openStream(streamCtx, url)
	if err != nil {
		cancel()
		return nil, err
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(channel)

		current := resp
		for {
			if current == nil {
				select {
				case <-time.After(retryDelay):
				case <-streamCtx.Done():
					return
				}
				r, err := ac.openStream(streamCtx, url)
				if err != nil {
					if streamCtx.Err() != nil {
						return
					}
					ac.log.Errorf("failed to reopen request stream: %v", err)
					continue
				}
				current = r
			}

			func() {
				defer current.Body.Close()
				dec := json.NewDecoder(current.Body)
				for {
					var event ReqEvent
					if err := dec.Decode(&event); err != nil {
						if streamCtx.Err() != nil {
							return
						}
						if errors.Is(err, io.EOF) {
							ac.log.Warn("request stream closed by server")
							return
						}
						ac.log.Errorf("failed to decode streamed request: %v", err)
						return
					}
					ac.log.Tracef("Received device request event record: %+v", event)
					select {
					case channel <- &event:
					case <-streamCtx.Done():
						return
					}
				}
			}()
			current = nil
		}
	}()

	var once sync.Once
	unsubscribe = func() {
		once.Do(func() {
			cancel()
			wg.Wait()
		})
	}
	return unsubscribe, nil
}

// SubscribeToDeviceLogs registers a new subscriber for logs emitted by the
// specified device.
//
// Matching log entries are delivered asynchronously to the provided channel.
// The optional match function is evaluated for each log entry; only entries
// for which match(entry) returns true are forwarded. If match is nil, all
// log entries are delivered.
//
// The streaming connection is opened synchronously: by the time this method
// returns, Adam has accepted the request and any subsequent log entries for
// the device will be delivered. On transient failures after the initial
// connection, a background goroutine reconnects with a fixed retry delay.
//
// The caller owns the provided channel and must ensure it is being drained.
// The channel will be closed automatically once the subscription is stopped.
//
// The returned unsubscribe function stops the background streaming goroutine,
// waits for it to exit, and guarantees that no more log entries will be sent
// to the channel after it returns. The function is idempotent and safe to call
// multiple times.
func (ac *AdamClient) SubscribeToDeviceLogs(
	devUUID uuid.UUID, channel chan<- *evelogs.LogEntry,
	match logger.LogEntryMatcher) (unsubscribe func(), err error) {
	const retryDelay = 3 * time.Second

	if err = ac.checkAdamRunning(); err != nil {
		return nil, err
	}

	// Verify device is known.
	ac.mutex.Lock()
	_, known := ac.knownDevices[devUUID]
	ac.mutex.Unlock()
	if !known {
		return nil, fmt.Errorf("unknown device UUID %q", devUUID)
	}

	streamCtx, cancel := context.WithCancel(context.Background())
	url := ac.adminURL("device/" + devUUID.String() + "/logs")

	resp, err := ac.openStream(streamCtx, url)
	if err != nil {
		cancel()
		return nil, err
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(channel)

		current := resp
		for {
			if current == nil {
				select {
				case <-time.After(retryDelay):
				case <-streamCtx.Done():
					return
				}
				r, err := ac.openStream(streamCtx, url)
				if err != nil {
					if streamCtx.Err() != nil {
						return
					}
					ac.log.Errorf("failed to reopen log stream: %v", err)
					continue
				}
				current = r
			}

			func() {
				defer current.Body.Close()
				dec := json.NewDecoder(current.Body)
				for {
					var raw json.RawMessage
					if err := dec.Decode(&raw); err != nil {
						if streamCtx.Err() != nil {
							return
						}
						if errors.Is(err, io.EOF) {
							ac.log.Warn("log stream closed by server")
							return
						}
						ac.log.Errorf("failed to decode streamed log entry: %v", err)
						return
					}
					entry := &evelogs.LogEntry{}
					if err := protojson.Unmarshal(raw, entry); err != nil {
						ac.log.Errorf(
							"failed to proto-unmarshal streamed log entry: %v", err)
						continue
					}
					if match != nil && !match(entry) {
						continue
					}
					select {
					case channel <- entry:
					case <-streamCtx.Done():
						return
					}
				}
			}()
			current = nil
		}
	}()

	var once sync.Once
	unsubscribe = func() {
		once.Do(func() {
			cancel()
			wg.Wait()
		})
	}
	return unsubscribe, nil
}

// IterateDeviceLogs retrieves all matching logs published so far by the given device
// and iterates over them using the provided DeviceLogIterator.
//
// If match is non-nil, only logs for which match(entry) returns true are iterated.
// If match is nil, all messages are iterated.
//
// If follow is true, the method subscribes to live log streaming after
// the initial GET completes and continues iterating new log entries until
// the provided context is canceled.
func (ac *AdamClient) IterateDeviceLogs(ctx context.Context, devUUID uuid.UUID,
	match logger.LogEntryMatcher, logIterator logger.DeviceLogIterator, follow bool) error {
	if err := ac.checkAdamRunning(); err != nil {
		return err
	}

	ac.mutex.Lock()
	_, known := ac.knownDevices[devUUID]
	ac.mutex.Unlock()
	if !known {
		return fmt.Errorf("unknown device UUID %q", devUUID)
	}

	// -------- Initial GET --------

	url := ac.adminURL("device/" + devUUID.String() + "/logs")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create GET %s request: %w", url, err)
	}

	resp, err := ac.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("GET %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status from GET %s: %d",
			url, resp.StatusCode)
	}

	dec := json.NewDecoder(resp.Body)

	for {
		var raw json.RawMessage

		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("failed to decode log entry JSON: %w", err)
		}

		entry := &evelogs.LogEntry{}
		if err = protojson.Unmarshal(raw, entry); err != nil {
			return fmt.Errorf("failed to proto-unmarshal log entry: %w", err)
		}
		if match == nil || match(entry) {
			stop, iterErr := logIterator.Iterate(entry)
			if iterErr != nil {
				return fmt.Errorf("failed to iterate log entry: %w", iterErr)
			}
			if stop {
				return nil
			}
		}
	}

	// -------- Follow mode --------

	if !follow {
		return nil
	}

	logCh := make(chan *evelogs.LogEntry, 100)
	unsubscribe, err := ac.SubscribeToDeviceLogs(devUUID, logCh, match)
	if err != nil {
		return err
	}
	defer unsubscribe()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case entry := <-logCh:
			stop, iterErr := logIterator.Iterate(entry)
			if iterErr != nil {
				return fmt.Errorf("failed to iterate log entry: %w", iterErr)
			}
			if stop {
				return nil
			}
		}
	}
}

// IterateAppLogs retrieves all matching logs published so far by the given
// application instance and iterates over them using the provided
// DeviceLogIterator.
//
// If match is non-nil, only logs for which match(entry) returns true are
// iterated. If match is nil, all entries are iterated.
//
// If follow is true, the method subscribes to live log streaming after the
// initial GET completes and continues iterating new log entries until the
// provided context is canceled.
func (ac *AdamClient) IterateAppLogs(ctx context.Context, devUUID, appUUID uuid.UUID,
	match logger.LogEntryMatcher, logIterator logger.DeviceLogIterator, follow bool) error {
	if err := ac.checkAdamRunning(); err != nil {
		return err
	}

	ac.mutex.Lock()
	_, known := ac.knownDevices[devUUID]
	ac.mutex.Unlock()
	if !known {
		return fmt.Errorf("unknown device UUID %q", devUUID)
	}

	// -------- Initial GET --------

	url := ac.adminURL("device/" + devUUID.String() + "/app/" + appUUID.String() + "/logs")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create GET %s request: %w", url, err)
	}

	resp, err := ac.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("GET %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status from GET %s: %d", url, resp.StatusCode)
	}

	dec := json.NewDecoder(resp.Body)

	for {
		var raw json.RawMessage

		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("failed to decode log entry JSON: %w", err)
		}

		entry := &evelogs.LogEntry{}
		if err = protojson.Unmarshal(raw, entry); err != nil {
			return fmt.Errorf("failed to proto-unmarshal log entry: %w", err)
		}
		if match == nil || match(entry) {
			stop, iterErr := logIterator.Iterate(entry)
			if iterErr != nil {
				return fmt.Errorf("failed to iterate log entry: %w", iterErr)
			}
			if stop {
				return nil
			}
		}
	}

	// -------- Follow mode --------

	if !follow {
		return nil
	}

	logCh := make(chan *evelogs.LogEntry, 100)
	unsubscribe, err := ac.SubscribeToAppLogs(devUUID, appUUID, logCh, match)
	if err != nil {
		return err
	}
	defer unsubscribe()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case entry := <-logCh:
			stop, iterErr := logIterator.Iterate(entry)
			if iterErr != nil {
				return fmt.Errorf("failed to iterate log entry: %w", iterErr)
			}
			if stop {
				return nil
			}
		}
	}
}

// SubscribeToAppLogs registers a new subscriber for logs emitted by the
// specified application instance.
//
// Matching log entries are delivered asynchronously to the provided channel.
// The optional match function is evaluated for each log entry; only entries
// for which match(entry) returns true are forwarded. If match is nil, all
// log entries are delivered.
//
// The streaming connection is opened synchronously: by the time this method
// returns, Adam has accepted the request and any subsequent log entries for
// the application will be delivered. On transient failures after the initial
// connection, a background goroutine reconnects with a fixed retry delay.
//
// The caller owns the provided channel and must ensure it is being drained.
// The channel will be closed automatically once the subscription is stopped.
//
// The returned unsubscribe function stops the background streaming goroutine,
// waits for it to exit, and guarantees that no more log entries will be sent
// to the channel after it returns. The function is idempotent and safe to call
// multiple times.
func (ac *AdamClient) SubscribeToAppLogs(
	devUUID, appUUID uuid.UUID, channel chan<- *evelogs.LogEntry,
	match logger.LogEntryMatcher) (unsubscribe func(), err error) {
	const retryDelay = 3 * time.Second

	if err = ac.checkAdamRunning(); err != nil {
		return nil, err
	}

	ac.mutex.Lock()
	_, known := ac.knownDevices[devUUID]
	ac.mutex.Unlock()
	if !known {
		return nil, fmt.Errorf("unknown device UUID %q", devUUID)
	}

	streamCtx, cancel := context.WithCancel(context.Background())
	url := ac.adminURL("device/" + devUUID.String() +
		"/app/" + appUUID.String() + "/logs")

	resp, err := ac.openStream(streamCtx, url)
	if err != nil {
		cancel()
		return nil, err
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(channel)

		current := resp
		for {
			if current == nil {
				select {
				case <-time.After(retryDelay):
				case <-streamCtx.Done():
					return
				}
				r, err := ac.openStream(streamCtx, url)
				if err != nil {
					if streamCtx.Err() != nil {
						return
					}
					ac.log.Errorf("failed to reopen app log stream: %v", err)
					continue
				}
				current = r
			}

			func() {
				defer current.Body.Close()
				dec := json.NewDecoder(current.Body)
				for {
					var raw json.RawMessage
					if err := dec.Decode(&raw); err != nil {
						if streamCtx.Err() != nil {
							return
						}
						if errors.Is(err, io.EOF) {
							ac.log.Warn("app log stream closed by server")
							return
						}
						ac.log.Errorf("failed to decode streamed app log entry: %v", err)
						return
					}
					entry := &evelogs.LogEntry{}
					if err := protojson.Unmarshal(raw, entry); err != nil {
						ac.log.Errorf(
							"failed to proto-unmarshal streamed app log entry: %v", err)
						continue
					}
					if match != nil && !match(entry) {
						continue
					}
					select {
					case channel <- entry:
					case <-streamCtx.Done():
						return
					}
				}
			}()
			current = nil
		}
	}()

	var once sync.Once
	unsubscribe = func() {
		once.Do(func() {
			cancel()
			wg.Wait()
		})
	}
	return unsubscribe, nil
}

// IterateDeviceInfoMsgs retrieves informational messages (ZInfoMsg)
// published by the specified device and passes matching messages to iterator.
//
// It first performs a one-shot GET request to fetch all currently available
// messages. If follow is true, it then subscribes to the streaming endpoint
// and continues delivering new messages until ctx is canceled.
//
// If match is non-nil, only messages for which match(msg) returns true
// are iterated. If match is nil, all messages are iterated.
func (ac *AdamClient) IterateDeviceInfoMsgs(ctx context.Context, devUUID uuid.UUID,
	match func(msg *eveinfo.ZInfoMsg) bool, iterator InfoMsgIterator, follow bool) error {
	if err := ac.checkAdamRunning(); err != nil {
		return err
	}

	ac.mutex.Lock()
	_, known := ac.knownDevices[devUUID]
	ac.mutex.Unlock()
	if !known {
		return fmt.Errorf("unknown device UUID %q", devUUID)
	}

	// -------- Initial GET --------

	url := ac.adminURL("device/" + devUUID.String() + "/info")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create GET %s request: %w", url, err)
	}

	resp, err := ac.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("GET %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status from GET %s: %d",
			url, resp.StatusCode)
	}

	dec := json.NewDecoder(resp.Body)

	for {
		var raw json.RawMessage

		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("failed to decode info message JSON: %w", err)
		}

		msg := &eveinfo.ZInfoMsg{}
		if err = protojson.Unmarshal(raw, msg); err != nil {
			return fmt.Errorf("failed to proto-unmarshal info message: %w", err)
		}
		if match == nil || match(msg) {
			stop, iterErr := iterator.Iterate(msg)
			if iterErr != nil {
				return fmt.Errorf("failed to iterate info message: %w", iterErr)
			}
			if stop {
				return nil
			}
		}
	}

	// -------- Follow mode --------

	if !follow {
		return nil
	}

	infoMsgCh := make(chan *eveinfo.ZInfoMsg, 100)
	unsubscribe, err := ac.SubscribeToDeviceInfoMsgs(devUUID, match, infoMsgCh)
	if err != nil {
		return err
	}
	defer unsubscribe()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg := <-infoMsgCh:
			stop, iterErr := iterator.Iterate(msg)
			if iterErr != nil {
				return fmt.Errorf("failed to iterate info message: %w", iterErr)
			}
			if stop {
				return nil
			}
		}
	}
}

// SubscribeToDeviceInfoMsgs subscribes to informational messages emitted
// by the specified device and delivers matching messages to channel.
//
// If match is non-nil, only messages for which match(msg) returns true
// are forwarded. If match is nil, all messages are delivered.
//
// The streaming connection is opened synchronously: by the time this method
// returns, Adam has accepted the request and any subsequent info messages
// for the device will be delivered. On transient failures after the initial
// connection, a background goroutine reconnects with a fixed retry delay.
//
// The returned unsubscribe function stops the background stream and waits
// for it to exit. It is safe to call multiple times. The channel is closed
// when the subscription ends.
func (ac *AdamClient) SubscribeToDeviceInfoMsgs(devUUID uuid.UUID,
	match func(msg *eveinfo.ZInfoMsg) bool,
	channel chan<- *eveinfo.ZInfoMsg) (unsubscribe func(), err error) {
	const retryDelay = 3 * time.Second

	if err = ac.checkAdamRunning(); err != nil {
		return nil, err
	}

	// Verify device is known.
	ac.mutex.Lock()
	_, known := ac.knownDevices[devUUID]
	ac.mutex.Unlock()
	if !known {
		return nil, fmt.Errorf("unknown device UUID %q", devUUID)
	}

	streamCtx, cancel := context.WithCancel(context.Background())
	url := ac.adminURL("device/" + devUUID.String() + "/info")

	resp, err := ac.openStream(streamCtx, url)
	if err != nil {
		cancel()
		return nil, err
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(channel)

		current := resp
		for {
			if current == nil {
				select {
				case <-time.After(retryDelay):
				case <-streamCtx.Done():
					return
				}
				r, err := ac.openStream(streamCtx, url)
				if err != nil {
					if streamCtx.Err() != nil {
						return
					}
					ac.log.Errorf("failed to reopen info message stream: %v", err)
					continue
				}
				current = r
			}

			func() {
				defer current.Body.Close()
				dec := json.NewDecoder(current.Body)
				for {
					var raw json.RawMessage
					if err := dec.Decode(&raw); err != nil {
						if streamCtx.Err() != nil {
							return
						}
						if errors.Is(err, io.EOF) {
							ac.log.Warn("info message stream closed by server")
							return
						}
						ac.log.Errorf("failed to decode streamed info message: %v", err)
						return
					}
					msg := &eveinfo.ZInfoMsg{}
					if err := protojson.Unmarshal(raw, msg); err != nil {
						ac.log.Errorf(
							"failed to proto-unmarshal streamed info message: %v", err)
						continue
					}
					if match != nil && !match(msg) {
						continue
					}
					select {
					case channel <- msg:
					case <-streamCtx.Done():
						return
					}
				}
			}()
			current = nil
		}
	}()

	var once sync.Once
	unsubscribe = func() {
		once.Do(func() {
			cancel()
			wg.Wait()
		})
	}
	return unsubscribe, nil
}

// IterateDeviceMetrics retrieves metric messages (ZMetricMsg) published by the
// specified device and passes them to iterator.
//
// It first performs a one-shot GET request to retrieve already published metrics.
// If follow is true, it then subscribes to the streaming endpoint
// and continues delivering new messages until ctx is canceled.
func (ac *AdamClient) IterateDeviceMetrics(ctx context.Context, devUUID uuid.UUID,
	iterator MetricMsgIterator, follow bool) error {
	if err := ac.checkAdamRunning(); err != nil {
		return err
	}

	ac.mutex.Lock()
	_, known := ac.knownDevices[devUUID]
	ac.mutex.Unlock()
	if !known {
		return fmt.Errorf("unknown device UUID %q", devUUID)
	}

	// -------- Initial GET --------

	url := ac.adminURL("device/" + devUUID.String() + "/metrics")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create GET %s request: %w", url, err)
	}

	resp, err := ac.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("GET %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status from GET %s: %d", url, resp.StatusCode)
	}

	dec := json.NewDecoder(resp.Body)
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("failed to decode metric message JSON: %w", err)
		}

		msg := &evemetrics.ZMetricMsg{}
		if err = protojson.Unmarshal(raw, msg); err != nil {
			return fmt.Errorf("failed to proto-unmarshal metric message: %w", err)
		}
		stop, iterErr := iterator.Iterate(msg)
		if iterErr != nil {
			return fmt.Errorf("failed to iterate metric message: %w", iterErr)
		}
		if stop {
			return nil
		}
	}

	// -------- Follow mode --------

	if !follow {
		return nil
	}

	metricMsgCh := make(chan *evemetrics.ZMetricMsg, 100)
	unsubscribe, err := ac.SubscribeToDeviceMetrics(devUUID, metricMsgCh)
	if err != nil {
		return err
	}
	defer unsubscribe()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg := <-metricMsgCh:
			stop, iterErr := iterator.Iterate(msg)
			if iterErr != nil {
				return fmt.Errorf("failed to iterate metric message: %w", iterErr)
			}
			if stop {
				return nil
			}
		}
	}
}

// SubscribeToDeviceMetrics subscribes to metric messages emitted
// by the specified device and delivers them to channel.
//
// The streaming connection is opened synchronously: by the time this method
// returns, Adam has accepted the request and any subsequent metric messages
// for the device will be delivered. On transient failures after the initial
// connection, a background goroutine reconnects with a fixed retry delay.
//
// The returned unsubscribe function stops the background stream and waits
// for it to exit. It is safe to call multiple times. The channel is closed
// when the subscription ends.
func (ac *AdamClient) SubscribeToDeviceMetrics(devUUID uuid.UUID,
	channel chan<- *evemetrics.ZMetricMsg) (unsubscribe func(), err error) {
	const retryDelay = 3 * time.Second

	if err = ac.checkAdamRunning(); err != nil {
		return nil, err
	}

	ac.mutex.Lock()
	_, known := ac.knownDevices[devUUID]
	ac.mutex.Unlock()
	if !known {
		return nil, fmt.Errorf("unknown device UUID %q", devUUID)
	}

	streamCtx, cancel := context.WithCancel(context.Background())
	url := ac.adminURL("device/" + devUUID.String() + "/metrics")

	resp, err := ac.openStream(streamCtx, url)
	if err != nil {
		cancel()
		return nil, err
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(channel)

		current := resp
		for {
			if current == nil {
				select {
				case <-time.After(retryDelay):
				case <-streamCtx.Done():
					return
				}
				r, err := ac.openStream(streamCtx, url)
				if err != nil {
					if streamCtx.Err() != nil {
						return
					}
					ac.log.Errorf("failed to reopen metrics stream: %v", err)
					continue
				}
				current = r
			}

			func() {
				defer current.Body.Close()
				dec := json.NewDecoder(current.Body)
				for {
					var raw json.RawMessage
					if err := dec.Decode(&raw); err != nil {
						if streamCtx.Err() != nil {
							return
						}
						if errors.Is(err, io.EOF) {
							ac.log.Warn("metrics stream closed by server")
							return
						}
						ac.log.Errorf("failed to decode streamed metric message: %v", err)
						return
					}
					msg := &evemetrics.ZMetricMsg{}
					if err := protojson.Unmarshal(raw, msg); err != nil {
						ac.log.Errorf(
							"failed to proto-unmarshal streamed metric message: %v", err)
						continue
					}
					select {
					case channel <- msg:
					case <-streamCtx.Done():
						return
					}
				}
			}()
			current = nil
		}
	}()

	var once sync.Once
	unsubscribe = func() {
		once.Do(func() {
			cancel()
			wg.Wait()
		})
	}
	return unsubscribe, nil
}

// findDeviceUUID searches Adam for a device with certificates/serial matching
// the given callback and returns its UUID if found.
func (ac *AdamClient) findDeviceUUID(ctx context.Context, httpClient *http.Client,
	match func(deviceCertPayload, uuid.UUID) bool) (uuid.UUID, bool, error) {

	url := ac.adminURL("device")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		err = fmt.Errorf("failed to create GET %s request: %w", url, err)
		return uuid.Nil, false, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("GET %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return uuid.Nil, false, fmt.Errorf(
			"unexpected status from GET %s: %s", url, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("failed to read GET %s response: %w", url, err)
		return uuid.Nil, false, err
	}

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	for _, line := range lines {
		id := strings.TrimSpace(line)
		if id == "" {
			continue
		}
		devUUID, err := uuid.FromString(id)
		if err != nil {
			ac.log.Warnf("Skipping invalid device UUID %q received from Adam", id)
			continue
		}

		devURL := ac.adminURL("device/" + devUUID.String())
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, devURL, nil)
		if err != nil {
			ac.log.Warnf("Failed to create GET %s request: %v", devURL, err)
			continue
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			ac.log.Warnf("GET %s failed: %v", devURL, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			ac.log.Warnf("GET %s returned status %s", devURL, resp.Status)
			continue
		}

		var payload deviceCertPayload
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			ac.log.Warnf("Failed to decode device payload for %s: %v", devUUID, err)
			continue
		}

		if match(payload, devUUID) {
			return devUUID, true, nil
		}
	}

	return uuid.Nil, false, nil
}

// findDeviceByCert searches Adam for a device registered with the given
// device certificate and returns its UUID if found.
func (ac *AdamClient) findDeviceByCert(ctx context.Context,
	httpClient *http.Client, devCert *x509.Certificate) (uuid.UUID, bool, error) {
	if devCert == nil {
		return uuid.Nil, false, errors.New("device certificate is nil")
	}

	return ac.findDeviceUUID(ctx, httpClient,
		func(payload deviceCertPayload, devUUID uuid.UUID) bool {
			block, _ := pem.Decode(payload.Cert)
			if block == nil {
				ac.log.Warnf("Device %s has invalid PEM certificate", devUUID)
				return false
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				ac.log.Warnf("Failed to parse device certificate for %s: %v",
					devUUID, err)
				return false
			}

			return cert.Equal(devCert)
		})
}

// findDeviceByOnboard searches Adam for a device onboarded with the given
// onboarding certificate and serial number and returns its UUID if found.
func (ac *AdamClient) findDeviceByOnboard(ctx context.Context, httpClient *http.Client,
	onboardCert *x509.Certificate, serial string) (uuid.UUID, bool, error) {
	if onboardCert == nil {
		return uuid.Nil, false, errors.New("onboarding certificate is nil")
	}
	if serial == "" {
		return uuid.Nil, false, errors.New("device serial is empty")
	}

	return ac.findDeviceUUID(ctx, httpClient,
		func(payload deviceCertPayload, devUUID uuid.UUID) bool {
			if payload.Serial != serial {
				return false
			}

			block, _ := pem.Decode(payload.Onboard)
			if block == nil {
				ac.log.Warnf("Device %s has invalid onboarding PEM", devUUID)
				return false
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				ac.log.Warnf("Failed to parse onboarding cert for %s: %v",
					devUUID, err)
				return false
			}

			return cert.Equal(onboardCert)
		})
}

// Generate server, signing and encryption certificates for Adam.
func (ac *AdamClient) generateCerts() (certDir string, err error) {
	certDir = filepath.Join(ac.runDir, "adam-certs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		err = fmt.Errorf("failed to create Adam cert directory: %w", err)
		return certDir, err
	}

	ac.log.Debug("Generating Adam TLS certificate")
	ac.tlsCert, ac.tlsKey, err = utils.GenServerCertElliptic(
		ac.caCert, ac.caKey, big.NewInt(1), ac.listenIPs,
		[]string{ac.hostname}, ac.hostname)
	if err != nil {
		err = fmt.Errorf("failed to generate Adam TLS certificate: %w", err)
		return certDir, err
	}
	err = utils.OutputCertAndKey(
		ac.tlsCert, ac.tlsKey,
		filepath.Join(certDir, "tls.pem"), filepath.Join(certDir, "tls-key.pem"))
	if err != nil {
		err = fmt.Errorf("failed to output Adam TLS certificate: %w", err)
		return certDir, err
	}

	ac.log.Debug("Generating Adam signing certificate")
	ac.signingCert, ac.signingKey, err = utils.GenServerCertElliptic(
		ac.caCert, ac.caKey, big.NewInt(2), ac.listenIPs,
		[]string{ac.hostname}, ac.hostname)
	if err != nil {
		err = fmt.Errorf("failed to generate Adam signing certificate: %w", err)
		return certDir, err
	}
	err = utils.OutputCertAndKey(
		ac.signingCert, ac.signingKey,
		filepath.Join(certDir, "signing.pem"), filepath.Join(certDir, "signing-key.pem"))
	if err != nil {
		err = fmt.Errorf("failed to output Adam signing certificate: %w", err)
		return certDir, err
	}

	ac.log.Debug("Generating Adam ECDH certificate")
	ac.ecdhCert, ac.ecdhKey, err = utils.GenServerCertElliptic(
		ac.caCert, ac.caKey, big.NewInt(3), ac.listenIPs,
		[]string{ac.hostname}, ac.hostname)
	if err != nil {
		err = fmt.Errorf("failed to generate Adam ECDH certificate: %w", err)
		return certDir, err
	}
	err = utils.OutputCertAndKey(
		ac.ecdhCert, ac.ecdhKey,
		filepath.Join(certDir, "ecdh.pem"), filepath.Join(certDir, "ecdh-key.pem"))
	if err != nil {
		err = fmt.Errorf("failed to output Adam ECDH certificate: %w", err)
		return certDir, err
	}
	return certDir, nil
}

// Publish Adam state update.
func (ac *AdamClient) publish(state AdamStateType, err error) {
	if ac.statusCh == nil {
		return
	}
	select {
	case ac.statusCh <- AdamState{Type: state, Err: err}:
	default:
		// Non-blocking: drop update if channel is full
	}
}

func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
