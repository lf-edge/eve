// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	hostapdBinary  = "/usr/sbin/hostapd"
	hostapdConfDir = "/etc/hostapd"
	hostapdRunDir  = "/run/hostapd"

	hostapdStartTimeout = 5 * time.Second
	hostapdStopTimeout  = 10 * time.Second
)

var macRE = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)

// Hostapd : Host access point daemon, used as 802.1x port authenticator.
type Hostapd struct {
	// DaemonName : logical name for the Hostapd instance.
	DaemonName string
	// Interface name of the bridge on which Hostapd should listen to.
	BridgeIfName string
	// CA certificate in PEM format.
	// Required for EAP-TLS, PEAP, and TTLS.
	CaCertPem string
	// CA private key in PEM format.
	// Required for EAP-TLS, PEAP, and TTLS.
	CaKeyPem string
	// List of allowed EAP users (supplicants) for authentication.
	Users []EAPUser
	// Re-authentication generation counter.
	// Whenever this value changes, all currently authenticated supplicants
	// are forcibly de-authenticated and required to re-authenticate.
	ReauthGeneration uint32
}

// EAPUser represents an individual EAP user for authentication.
type EAPUser struct {
	// User identity (EAP-Identity) presented during authentication.
	// Supports hostapd-style wildcards:
	//
	//	"*" : matches any identity
	//	"<prefix>*" : matches any identity starting with the given prefix
	Identity string
	// Allowed EAP methods for this user.
	Methods []api.EAPMethod
	// Optional password for password-based EAP methods (e.g., PEAP, TTLS).
	// Not used for certificate-based EAP-TLS.
	Password string
}

func equalEAPUsers(u1, u2 EAPUser) bool {
	return u1.Identity == u2.Identity &&
		generics.EqualSets(u1.Methods, u2.Methods) &&
		u1.Password == u2.Password
}

// Name of the Hostapd instance.
func (h Hostapd) Name() string {
	return h.DaemonName
}

// Label assigned to the Hostapd instance.
func (h Hostapd) Label() string {
	return h.DaemonName + " (Host access point daemon)"
}

// Type assigned to Hostapd.
func (h Hostapd) Type() string {
	return HostapdTypename
}

// Equal is a comparison method for two equally-named Hostapd instances.
func (h Hostapd) Equal(other depgraph.Item) bool {
	h2 := other.(Hostapd)
	return h.BridgeIfName == h2.BridgeIfName &&
		h.CaCertPem == h2.CaCertPem &&
		h.CaKeyPem == h2.CaKeyPem &&
		generics.EqualSetsFn(h.Users, h2.Users, equalEAPUsers) &&
		h.ReauthGeneration == h2.ReauthGeneration
}

// External returns false.
func (h Hostapd) External() bool {
	return false
}

// String describes the Hostapd instance.
func (h Hostapd) String() string {
	return fmt.Sprintf("Host access point daemon: %#+v", h)
}

// Dependencies lists the bridge as the only dependency.
func (h Hostapd) Dependencies() (deps []depgraph.Dependency) {
	deps = append(deps, depgraph.Dependency{
		RequiredItem: depgraph.ItemRef{
			ItemType: BridgeTypename,
			ItemName: h.BridgeIfName,
		},
		Description: "Bridge interface must exist",
	})
	return deps
}

// PNACEvent represents a port-based network access control (802.1X) event
// reported by hostapd for a bridged interface.
type PNACEvent struct {
	InterfaceName   string
	IsAuthenticated bool
}

// HostapdConfigurator implements Configurator interface for Hostapd.
type HostapdConfigurator struct {
	sync.Mutex
	PNACEventPublishCh chan<- PNACEvent
	eventWatchers      map[string]*eventWatcher
}

type eventWatcher struct {
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

// Create starts Hostapd.
func (c *HostapdConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	config := item.(Hostapd)
	if err := prepareHostapdCertificates(config); err != nil {
		return err
	}
	if err := createHostapdConfFile(config); err != nil {
		return err
	}
	if err := createHostapdEAPUsersFile(config); err != nil {
		return err
	}
	if err := setBridgeEAPOLForwarding(config.BridgeIfName, true); err != nil {
		return err
	}
	if err := setBridgePromiscuousMode(config.BridgeIfName, true); err != nil {
		return err
	}
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		deadline := time.Now().Add(hostapdStartTimeout)
		if err := startHostapd(config); err != nil {
			log.Error(err)
			done(err)
			return
		}

		// Wait for hostapd control socket to appear.
		ctrlSocket := hostapdCtrlSocket(config.BridgeIfName)
		for {
			if _, err := os.Stat(ctrlSocket); err == nil {
				break
			}
			if time.Now().After(deadline) {
				err := fmt.Errorf("hostapd ctrl socket %s did not appear", ctrlSocket)
				log.Error(err)
				done(err)
				return
			}
			time.Sleep(200 * time.Millisecond)
		}

		if c.PNACEventPublishCh == nil {
			done(nil)
			return
		}

		script, err := createHostapdEventScript(config)
		if err != nil {
			done(err)
			return
		}

		ctrl := hostapdCtrlSocketDir()
		cmd := exec.Command("hostapd_cli", "-p", ctrl, "-a", script)
		if err = cmd.Start(); err != nil {
			err = fmt.Errorf("failed to register hostapd event script")
			log.Error(err)
			done(err)
			return
		}

		c.Lock()
		if c.eventWatchers == nil {
			c.eventWatchers = make(map[string]*eventWatcher)
		}
		watcher := &eventWatcher{}
		watcher.ctx, watcher.cancel = context.WithCancel(context.Background())
		c.eventWatchers[config.DaemonName] = watcher
		c.Unlock()
		_ = runHostapdEventWatcher(watcher, config.DaemonName, c.PNACEventPublishCh)
		done(nil)
	}()
	return nil
}

// Modify is able to apply change in ReauthGeneration, deauthenticate all connected ports.
func (c *HostapdConfigurator) Modify(ctx context.Context,
	_, newItem depgraph.Item) (err error) {
	config := newItem.(Hostapd)
	return deauthenticateAllPorts(config)
}

// Delete stops Hostapd.
func (c *HostapdConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	config := item.(Hostapd)
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		if err := deauthenticateAllPorts(config); err != nil {
			done(err)
			return
		}
		// Wait for hostapd de-authenticate events to get processed.
		time.Sleep(3 * time.Second)
		c.Lock()
		if watcher := c.eventWatchers[config.DaemonName]; watcher != nil {
			watcher.cancel()
			watcher.wg.Wait()
			delete(c.eventWatchers, config.DaemonName)
		}
		c.Unlock()
		err := stopHostapd(config.DaemonName)
		if err == nil {
			// ignore errors from here
			_ = setBridgeEAPOLForwarding(config.BridgeIfName, false)
			_ = setBridgePromiscuousMode(config.BridgeIfName, false)
			_ = removeHostapdConfFile(config.DaemonName)
			_ = removeHostapdEAPUsersFile(config.DaemonName)
			_ = removeHostapdCtrlSocket(config.BridgeIfName)
			_ = removeHostapdLogFile(config.DaemonName)
			_ = removeHostapdPidFile(config.DaemonName)
			_ = removeHostapdEventScript(config.DaemonName)
			_ = removeHostapdEventSocket(config.DaemonName)
			_ = removeHostapdCertDir(config.DaemonName)
		}
		done(err)
	}()
	return nil
}

// NeedsRecreate always returns true if anything besides ReauthGeneration changes.
func (c *HostapdConfigurator) NeedsRecreate(
	oldItem, newItem depgraph.Item) (recreate bool) {
	h1 := oldItem.(Hostapd)
	h2 := newItem.(Hostapd)
	return h1.BridgeIfName != h2.BridgeIfName ||
		h1.CaCertPem != h2.CaCertPem ||
		h1.CaKeyPem != h2.CaKeyPem ||
		!generics.EqualSetsFn(h1.Users, h2.Users, equalEAPUsers)
}

func hostapdConfigPath(daemonName string) string {
	return filepath.Join(hostapdConfDir, daemonName+".conf")
}

func hostapdEAPUsersFile(daemonName string) string {
	return filepath.Join(hostapdConfDir, daemonName+".eap_users")
}

func hostapdCtrlSocketDir() string {
	return filepath.Join(hostapdRunDir, "ctrl-sock")
}

func hostapdCtrlSocket(brIfName string) string {
	return filepath.Join(hostapdCtrlSocketDir(), brIfName)
}

func hostapdPidFile(daemonName string) string {
	return filepath.Join(hostapdRunDir, daemonName+".pid")
}

func hostapdLogFile(daemonName string) string {
	return filepath.Join(hostapdRunDir, daemonName+".log")
}

func hostapdCertDir(daemonName string) string {
	return filepath.Join(hostapdRunDir, daemonName+"-certs")
}

func hostapdEventSocket(daemonName string) string {
	return filepath.Join(hostapdRunDir, daemonName+"-events.sock")
}

func hostapdEventScript(daemonName string) string {
	// "/run" is a tmpfs, mounted with noexec.
	return filepath.Join("/usr/local/bin", "hostapd-"+daemonName+"-on-auth-event.sh")
}

func removeHostapdConfFile(daemonName string) error {
	configPath := hostapdConfigPath(daemonName)
	if err := os.Remove(configPath); err != nil {
		err = fmt.Errorf("failed to remove hostapd config file %s: %w",
			configPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func removeHostapdEAPUsersFile(daemonName string) error {
	eapUsersPath := hostapdEAPUsersFile(daemonName)
	if err := os.Remove(eapUsersPath); err != nil {
		err = fmt.Errorf("failed to remove hostapd EAP-users file %s: %w",
			eapUsersPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func removeHostapdCtrlSocket(brIfName string) error {
	ctrlSocket := hostapdCtrlSocket(brIfName)
	if err := os.Remove(ctrlSocket); err != nil {
		err = fmt.Errorf("failed to remove hostapd control socket %s: %w",
			ctrlSocket, err)
		log.Error(err)
		return err
	}
	return nil
}

func removeHostapdPidFile(daemonName string) error {
	pidPath := hostapdPidFile(daemonName)
	if err := os.Remove(pidPath); err != nil {
		err = fmt.Errorf("failed to remove hostapd PID file %s: %w",
			pidPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func removeHostapdLogFile(daemonName string) error {
	logPath := hostapdLogFile(daemonName)
	if err := os.Remove(logPath); err != nil {
		err = fmt.Errorf("failed to remove hostapd log file %s: %w",
			logPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func removeHostapdCertDir(daemonName string) error {
	dirPath := hostapdCertDir(daemonName)
	if err := os.RemoveAll(dirPath); err != nil {
		err = fmt.Errorf("failed to remove hostapd certificate directory %s: %w",
			dirPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func removeHostapdEventScript(daemonName string) error {
	scriptPath := hostapdEventScript(daemonName)
	if err := os.Remove(scriptPath); err != nil {
		err = fmt.Errorf("failed to remove hostapd event script %s: %w",
			scriptPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func removeHostapdEventSocket(daemonName string) error {
	eventSocket := hostapdEventSocket(daemonName)
	if err := os.Remove(eventSocket); err != nil {
		err = fmt.Errorf("failed to remove hostapd event socket %s: %w",
			eventSocket, err)
		log.Error(err)
		return err
	}
	return nil
}

func deauthenticateAllPorts(config Hostapd) error {
	ctrl := hostapdCtrlSocketDir()

	out, err := exec.Command("hostapd_cli", "-p", ctrl, "-i", config.BridgeIfName,
		"all_sta").CombinedOutput()
	if err != nil {
		err = fmt.Errorf("hostapd_cli all_sta failed: %w", err)
		log.Error(err)
		return err
	}

	for _, line := range strings.Split(string(out), "\n") {
		if macRE.MatchString(line) {
			err = exec.Command("hostapd_cli", "-p", ctrl, "-i", config.BridgeIfName,
				"deauthenticate", line).Run()
			if err != nil {
				err = fmt.Errorf("hostapd_cli deauthenticate %q failed: %w", line, err)
				log.Error(err)
				return err
			}
		}
	}
	return nil
}

func createHostapdEventScript(config Hostapd) (string, error) {
	sock := hostapdEventSocket(config.DaemonName)
	script := hostapdEventScript(config.DaemonName)

	content := fmt.Sprintf(`#!/bin/sh
EVENT="$2"
MAC="$3"
BRIDGE="%s"

printf "%%s %%s %%s\n" "$EVENT" "$MAC" "$BRIDGE" | socat - UNIX-CONNECT:%s
`, config.BridgeIfName, sock)

	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		err = fmt.Errorf("failed to write hostapd event script %s: %w", script, err)
		log.Error(err)
		return "", err
	}
	return script, nil
}

func runHostapdEventWatcher(
	watcher *eventWatcher, daemon string, publishCh chan<- PNACEvent) error {
	sockPath := hostapdEventSocket(daemon)
	_ = os.Remove(sockPath)

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		err = fmt.Errorf("failed to listen on event socket %s: %w", sockPath, err)
		log.Error(err)
		return err
	}

	// Ensure Accept() unblocks when context is cancelled
	watcher.wg.Add(1)
	go func() {
		defer watcher.wg.Done()
		<-watcher.ctx.Done()
		_ = l.Close()
	}()

	watcher.wg.Add(1)
	go func() {
		defer watcher.wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-watcher.ctx.Done():
					return // graceful shutdown
				default:
					err = fmt.Errorf("accept failed on %s: %w", sockPath, err)
					log.Error(err)
					return
				}
			}

			watcher.wg.Add(1)
			go handleEventConn(watcher, conn, publishCh)
		}
	}()
	return nil
}

func handleEventConn(watcher *eventWatcher, conn net.Conn, publishCh chan<- PNACEvent) {
	defer watcher.wg.Done()
	defer func() {
		if err := conn.Close(); err != nil {
			log.Warnf("Failed to close hostapd event connection: %v", err)
		}
	}()

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		log.Errorf("Failed to read hostapd event data: %v", err)
		return
	}
	if n == 0 {
		log.Errorf("Received empty hostapd event data")
		return
	}

	fields := strings.Fields(string(buf[:n]))
	if len(fields) < 3 {
		// expected: <event> <mac> <bridge>
		log.Errorf("Expected hostapd event data with 3 fields, instead received: %v",
			fields)
		return
	}
	log.Infof("Received new hostapd event: %v", fields)

	event := fields[0]
	mac := fields[1]
	bridge := fields[2]

	var isAuthenticated bool
	switch event {
	case "CTRL-EVENT-EAP-SUCCESS",
		"CTRL-EVENT-EAP-SUCCESS2",
		"AP-STA-CONNECTED":
		isAuthenticated = true
	case "CTRL-EVENT-EAP-FAILURE",
		"AP-STA-DISCONNECTED":
		isAuthenticated = false
	default:
		log.Warnf("unhandled hostapd event: %s", event)
		return
	}

	portIfName, err := bridgePortForNeighMAC(bridge, mac)
	if err != nil {
		log.Warnf("failed to resolve output port for neighbour MAC %s on bridge %s: %v",
			mac, bridge, err)
		return
	}
	if portIfName == "" {
		log.Warnf("None of the bridge %s ports is matching neighbour MAC %s",
			bridge, mac)
		return
	}

	pnacEvent := PNACEvent{
		InterfaceName:   portIfName,
		IsAuthenticated: isAuthenticated,
	}
	log.Infof("Publishing PNAC event: %+v", pnacEvent)
	select {
	case publishCh <- pnacEvent:
	case <-watcher.ctx.Done():
		log.Warnf("PNAC event %v was discarded", pnacEvent)
	}
}

func bridgePortForNeighMAC(bridgeIf string, mac string) (string, error) {
	br, err := netlink.LinkByName(bridgeIf)
	if err != nil {
		return "", err
	}
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return "", err
	}
	fdbs, err := netlink.NeighList(0, unix.AF_BRIDGE)
	if err != nil {
		return "", err
	}

	for _, fdb := range fdbs {
		if fdb.MasterIndex != br.Attrs().Index {
			continue
		}
		if !bytes.Equal(fdb.HardwareAddr, hw) {
			continue
		}
		link, err := netlink.LinkByIndex(fdb.LinkIndex)
		if err != nil {
			continue
		}
		return link.Attrs().Name, nil
	}

	return "", nil
}

func prepareHostapdCertificates(config Hostapd) error {
	dir := hostapdCertDir(config.DaemonName)
	if err := ensureDir(dir); err != nil {
		return err
	}

	caCertPath := filepath.Join(dir, "ca.pem")
	err := os.WriteFile(caCertPath, []byte(config.CaCertPem), 0o644)
	if err != nil {
		err = fmt.Errorf("failed to write hostapd CA cert %s: %w", caCertPath, err)
		log.Error(err)
		return err
	}
	return generateServerCert(config)
}

func generateServerCert(config Hostapd) error {
	// Parse CA certificate
	caCertBlock, _ := pem.Decode([]byte(config.CaCertPem))
	if caCertBlock == nil || caCertBlock.Type != "CERTIFICATE" {
		err := fmt.Errorf("failed to decode CA certificate PEM")
		log.Error(err)
		return err
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		err = fmt.Errorf("failed to parse CA certificate: %w", err)
		log.Error(err)
		return err
	}

	// Parse CA private key (expects RSA)
	caKeyBlock, _ := pem.Decode([]byte(config.CaKeyPem))
	if caKeyBlock == nil {
		err = fmt.Errorf("failed to decode CA private key PEM")
		log.Error(err)
		return err
	}
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		err = fmt.Errorf("failed to parse CA private key: %w", err)
		log.Error(err)
		return err
	}

	// Generate server private key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		err = fmt.Errorf("failed to generate server private key: %w", err)
		log.Error(err)
		return err
	}

	// Server certificate template
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		err = fmt.Errorf("failed to generate serial number: %w", err)
		log.Error(err)
		return err
	}

	serverCertTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "hostapd-" + config.DaemonName,
		},
		NotBefore: time.Now().Add(-5 * time.Minute),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	// Create and sign server certificate
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverCertTmpl,
		caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		err = fmt.Errorf("failed to sign server certificate: %w", err)
		log.Error(err)
		return err
	}

	// Write server key
	certDir := hostapdCertDir(config.DaemonName)
	serverKeyPath := filepath.Join(certDir, "server.key")
	err = os.WriteFile(serverKeyPath,
		pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
		}), 0o600)
	if err != nil {
		err = fmt.Errorf("failed to write server key: %w", err)
		log.Error(err)
		return err
	}

	// Write server certificate
	serverCertPath := filepath.Join(certDir, "server.pem")
	err = os.WriteFile(serverCertPath,
		pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: serverCertDER,
		}), 0o644)
	if err != nil {
		err = fmt.Errorf("failed to write server certificate: %w", err)
		log.Error(err)
		return err
	}

	return nil
}

func createHostapdConfFile(config Hostapd) error {
	if err := ensureDir(hostapdConfDir); err != nil {
		return err
	}
	cfgPath := hostapdConfigPath(config.DaemonName)
	file, err := os.Create(cfgPath)
	if err != nil {
		err = fmt.Errorf("failed to create hostapd config file %s: %w", cfgPath, err)
		log.Error(err)
		return err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			log.Warnf("Failed to close hostapd config file %s: %v", cfgPath, cerr)
		}
	}()
	eapUsersFile := hostapdEAPUsersFile(config.DaemonName)
	certDir := hostapdCertDir(config.DaemonName)

	_, err = fmt.Fprintf(file, `
interface=%s
driver=wired

ieee8021x=1
eapol_version=2
eap_server=1

ctrl_interface=%s
ctrl_interface_group=0

eap_user_file=%s

# Certificates for EAP-TLS
ca_cert=%s/ca.pem
server_cert=%s/server.pem
private_key=%s/server.key
private_key_passwd=

logger_stdout=-1
logger_stdout_level=2

# Allow only EAP-TLS method
eap_message=hello
`,
		config.BridgeIfName,
		hostapdCtrlSocketDir(),
		eapUsersFile,
		certDir,
		certDir,
		certDir,
	)
	if err != nil {
		err = fmt.Errorf("failed to write hostapd config file %s: %w", cfgPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func createHostapdEAPUsersFile(config Hostapd) error {
	if err := ensureDir(dnsmasqConfDir); err != nil {
		return err
	}
	eapUsersPath := hostapdEAPUsersFile(config.DaemonName)
	file, err := os.Create(eapUsersPath)
	if err != nil {
		err = fmt.Errorf("failed to create hostapd EAP users file %s: %w",
			eapUsersPath, err)
		log.Error(err)
		return err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			log.Warnf("Failed to close hostapd EAP users file %s: %v", eapUsersPath, cerr)
		}
	}()

	for _, u := range config.Users {
		var methods []string
		for _, m := range u.Methods {
			method, err := eapMethodToString(m)
			if err != nil {
				return err
			}
			methods = append(methods, method)
		}
		if u.Password != "" {
			_, err = fmt.Fprintf(file, "\"%s\" %s \"%s\"\n",
				u.Identity, strings.Join(methods, ","), u.Password)
		} else {
			_, err = fmt.Fprintf(file, "\"%s\" %s\n",
				u.Identity, strings.Join(methods, ","),
			)
		}
		if err != nil {
			err = fmt.Errorf("failed to write hostapd EAP users file %s: %w",
				eapUsersPath, err)
			log.Error(err)
			return err
		}
	}
	return nil
}

func eapMethodToString(m api.EAPMethod) (string, error) {
	switch m {
	case api.EAPMethod_EAP_METHOD_TLS:
		return "TLS", nil
	case api.EAPMethod_EAP_METHOD_PEAP:
		return "PEAP", nil
	case api.EAPMethod_EAP_METHOD_TTLS:
		return "TTLS", nil
	case api.EAPMethod_EAP_METHOD_MD5:
		return "MD5", nil
	default:
		return "", fmt.Errorf("unsupported EAP method: %v", m)
	}
}

func setBridgeEAPOLForwarding(brIfName string, enable bool) error {
	groupFwdMask := "0"
	if enable {
		// Bit 3 (0x8) enables forwarding of 01:80:c2:00:00:03 (EAPOL)
		groupFwdMask = "8"
	}

	path := fmt.Sprintf("/sys/class/net/%s/bridge/group_fwd_mask", brIfName)
	if err := os.WriteFile(path, []byte(groupFwdMask), 0o644); err != nil {
		err = fmt.Errorf("failed to set EAPOL forwarding on bridge %s: %w",
			brIfName, err)
		log.Error(err)
		return err
	}
	return nil
}

// setBridgePromiscuousMode enables or disables promiscuous mode on the bridge interface.
func setBridgePromiscuousMode(brIfName string, enable bool) error {
	link, err := netlink.LinkByName(brIfName)
	if err != nil {
		return fmt.Errorf("failed to find bridge %s: %w", brIfName, err)
	}
	if enable {
		if err := netlink.SetPromiscOn(link); err != nil {
			return fmt.Errorf("failed to enable promiscuous mode on %s: %w",
				brIfName, err)
		}
	} else {
		if err := netlink.SetPromiscOff(link); err != nil {
			return fmt.Errorf("failed to disable promiscuous mode on %s: %w",
				brIfName, err)
		}
	}
	return nil
}

func startHostapd(config Hostapd) error {
	if err := ensureDir(hostapdRunDir); err != nil {
		return err
	}

	cmd := hostapdBinary
	pidFile := hostapdPidFile(config.DaemonName)
	logFile := hostapdLogFile(config.DaemonName)
	args := []string{
		"-dd",
		hostapdConfigPath(config.DaemonName),
	}
	return startProcess(MainNsName, cmd, args, pidFile, logFile,
		hostapdStartTimeout, true, true)
}

func stopHostapd(daemonName string) error {
	pidFile := hostapdPidFile(daemonName)
	return stopProcess(pidFile, hostapdStopTimeout)
}
