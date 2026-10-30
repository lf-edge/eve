// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/proc"
	"golang.org/x/sys/unix"
)

// Put config and PID files into the run directory of NIM.
const nimRunDir = "/run/nim"

const (
	wpaSupplicantStartTimeout = 5 * time.Second
	wpaSupplicantStopTimeout  = 10 * time.Second
)

// WpaSupplicant represents a Wi-Fi Protected Access client and IEEE 802.1X supplicant.
// It defines authentication configuration for a specific network adapter.
// See: https://linux.die.net/man/8/wpa_supplicant
type WpaSupplicant struct {
	// AdapterLL is the logical label of the target network adapter.
	AdapterLL string

	// AdapterIfName is the OS-level interface name of the target adapter.
	AdapterIfName string

	// Exactly one of WiFiConfigs or PNACConfig must be configured:

	// WiFiConfigs defines SSID-based Wi-Fi network configurations using
	// username/password authentication.
	// Supports WPA/WPA2 Personal (PSK) and password-based Enterprise Wi-Fi
	// networks (PEAP).
	WiFiConfigs []WifiConfig

	// PNACConfig defines port-based IEEE 802.1X configuration using EAP-TLS.
	// Intended for port-based network access control (PNAC) of physical adapters,
	// rather than for SSID-based Wi-Fi networks.
	PNACConfig *PNAC8021XConfig
}

// WifiConfig defines SSID-based Wi-Fi network configuration.
// Supports WPA/WPA2 Personal (PSK) and password-based Enterprise (PEAP)
// Wi-Fi authentication.
type WifiConfig struct {
	// SSID is the name of the Wi-Fi network to connect to.
	SSID string

	// KeyScheme specifies the Wi-Fi key management scheme (WPA-PSK, WPA-EAP).
	KeyScheme types.WifiKeySchemeType

	// Identity used for password-based Enterprise Wi-Fi authentication.
	// Ignored for personal (PSK-based) networks.
	Identity string

	// Pre-hashed EAP password in wpa_supplicant format.
	// The value must be generated using `wpa_passphrase`, which derives a
	// PBKDF2-HMAC-SHA1 hash from the plaintext password and the network SSID.
	PasswordHash string

	// Priority controls the preference of this network when multiple networks
	// are available. Higher values are preferred. Zero (default) means lowest priority.
	Priority int32
}

// String returns human-readable WifiConfig description without the sensitive
// password hash.
func (c WifiConfig) String() string {
	return fmt.Sprintf("SSID=%q, KeyScheme=%s, Identity=%q, Priority=%d",
		c.SSID, c.KeyScheme.ToProto().String(), c.Identity, c.Priority)
}

// PNAC8021XConfig defines per-port IEEE 802.1X configuration using EAP-TLS.
// This is typically used for port-based network access control (PNAC)
// on physical adapters.
type PNAC8021XConfig struct {
	// Optional EAP identity presented during authentication.
	// May differ from the certificate subject or SAN.
	EAPIdentity string

	// CACertBundlePath is the filesystem path to a PEM-encoded CA certificate
	// bundle used to verify the authentication server’s TLS certificate.
	// The bundle is persisted by scepclient and includes trust anchors plus
	// any verified intermediate CA certs received from the SCEP server.
	CACertBundlePath string

	// Path to the client certificate used for EAP-TLS authentication.
	ClientCertPath string

	// Path to the client private key used for EAP-TLS authentication.
	ClientKeyPath string
}

// Equal is a comparison method for PNAC8021XConfig.
func (c *PNAC8021XConfig) Equal(other *PNAC8021XConfig) bool {
	if c == nil || other == nil {
		return c == other
	}
	return c.EAPIdentity == other.EAPIdentity &&
		c.CACertBundlePath == other.CACertBundlePath &&
		c.ClientCertPath == other.ClientCertPath &&
		c.ClientKeyPath == other.ClientKeyPath
}

// String returns a human-readable description of PNAC8021XConfig.
// Only certificate subjects are included (not full certificates).
func (c *PNAC8021XConfig) String() string {
	if c == nil {
		return "<nil>"
	}
	return fmt.Sprintf(
		"EAPIdentity=%q, CACertBundlePath=%q, ClientCertPath=%q, ClientKeyPath=%q",
		c.EAPIdentity,
		c.CACertBundlePath,
		c.ClientCertPath,
		c.ClientKeyPath,
	)
}

// Name is based on the adapter interface name (one supplicant per interface).
func (s WpaSupplicant) Name() string {
	return s.AdapterIfName
}

// Label is more human-readable than name.
func (s WpaSupplicant) Label() string {
	return "wpa_supplicant for " + s.AdapterLL
}

// Type of the item.
func (s WpaSupplicant) Type() string {
	return WpaSupplicantTypename
}

// Equal is a comparison method for two equally-named WpaSupplicant instances.
func (s WpaSupplicant) Equal(other depgraph.Item) bool {
	s2, isWpaSupplicant := other.(WpaSupplicant)
	if !isWpaSupplicant {
		return false
	}
	return generics.EqualSets(s.WiFiConfigs, s2.WiFiConfigs) &&
		s.PNACConfig.Equal(s2.PNACConfig)
}

// External returns false.
func (s WpaSupplicant) External() bool {
	return false
}

// String returns a human-readable description of the wpa_supplicant configuration.
func (s WpaSupplicant) String() string {
	switch {
	case len(s.WiFiConfigs) > 0:
		var networks []string
		for _, cfg := range s.WiFiConfigs {
			networks = append(networks, cfg.String())
		}
		return fmt.Sprintf(
			"WPA supplicant (Wi-Fi): adapter=%s (%s), Networks=%v",
			s.AdapterLL, s.AdapterIfName, networks)

	case s.PNACConfig != nil:
		return fmt.Sprintf(
			"WPA supplicant (802.1X): adapter=%s (%s), %s",
			s.AdapterLL, s.AdapterIfName, s.PNACConfig)

	default:
		return fmt.Sprintf(
			"WPA supplicant: adapter=%s (%s), no configuration",
			s.AdapterLL, s.AdapterIfName)
	}
}

type wirelessTypeGetter interface {
	GetWirelessType() types.WirelessType
}

// Dependencies lists the adapter as the only dependency of the wpa_supplicant.
func (s WpaSupplicant) Dependencies() (deps []depgraph.Dependency) {
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: AdapterTypename,
				ItemName: s.AdapterIfName,
			},
			MustSatisfy: func(item depgraph.Item) bool {
				adapter, ok := item.(wirelessTypeGetter)
				if !ok {
					// Unreachable, linuxitems.Adapter implements GetWirelessType().
					return false
				}
				if len(s.WiFiConfigs) > 0 {
					return adapter.GetWirelessType() == types.WirelessTypeWifi
				}
				return adapter.GetWirelessType() == types.WirelessTypeNone // Ethernet
			},
			Description: "Network adapter must exist",
		},
	}
}

// WpaSupplicantConfigurator implements Configurator interface (libs/reconciler)
// for WpaSupplicant.
type WpaSupplicantConfigurator struct {
	Log          *base.LogObject
	procManagers map[string]*processManagers // key: interface name
}

type processManagers struct {
	supplicantPM *proc.ProcessManager
	// Stops the goroutine delivering 802.1X events (nil if PNAC is not used).
	stopWatcher context.CancelFunc
	watcherDone chan struct{}
}

// Create prepares config file and starts wpa_supplicant.
func (c *WpaSupplicantConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	s, ok := item.(WpaSupplicant)
	if !ok {
		return fmt.Errorf("invalid item type %T, expected WpaSupplicant", item)
	}

	if c.procManagers == nil {
		c.procManagers = make(map[string]*processManagers)
	}

	if err := c.createConfigFile(s); err != nil {
		return err
	}

	if s.PNACConfig != nil {
		stateDir := filepath.Dir(c.pnacStatePath(s.AdapterIfName))
		if err := os.MkdirAll(stateDir, 0755); err != nil {
			err = fmt.Errorf("failed to create PNAC state dir: %w", err)
			c.Log.Error(err)
			return err
		}
	}

	pms := &processManagers{
		supplicantPM: c.initPMForSupplicant(s),
	}
	c.procManagers[s.AdapterIfName] = pms

	done := reconciler.ContinueInBackground(ctx)
	go func() {
		ctx, cancel := context.WithTimeout(ctx, wpaSupplicantStartTimeout)
		err := pms.supplicantPM.Start(ctx)
		if err != nil {
			err = fmt.Errorf("failed to start wpa_supplicant: %w", err)
			c.Log.Error(err)
			cancel()
			done(err)
			return
		}

		if s.PNACConfig != nil {
			watcherCtx, stopWatcher := context.WithCancel(context.Background())
			pms.stopWatcher = stopWatcher
			pms.watcherDone = make(chan struct{})
			go func() {
				defer close(pms.watcherDone)
				c.watchPNACEvents(watcherCtx, s.AdapterIfName)
			}()
		}

		cancel()
		done(nil)
	}()
	return nil
}

func (c *WpaSupplicantConfigurator) initPMForSupplicant(
	s WpaSupplicant) *proc.ProcessManager {
	// Determine the appropriate driver
	var driver string
	switch {
	case len(s.WiFiConfigs) > 0:
		driver = "nl80211,wext" // try modern driver first, then legacy
	case s.PNACConfig != nil:
		driver = "wired" // Wired PNAC / 802.1X
	default:
		driver = "none" // No interface configured (should be rare)
	}

	args := []string{
		"-i", s.AdapterIfName,
		"-c", c.configPath(s.AdapterIfName),
		"-D", driver, // explicitly set driver
		"-d", // increase debugging verbosity
	}
	return &proc.ProcessManager{
		Log:  c.Log,
		Cmd:  "wpa_supplicant",
		Args: args,

		// In Alpine, wpa_supplicant is built without syslog support (CONFIG_DEBUG_SYSLOG),
		// so the "-s" option is unavailable. To ensure logs are visible in EVE,
		// we run the process in the foreground (without -B) and let ProcessManager capture
		// stdout and stderr, forwarding them through the NIM logger.
		WillFork:  false,
		LogOutput: true,
	}
}

// watchPNACEvents maintains a per-interface "pnac.state" file containing:
//
//	STATE: <CONNECTED|DISCONNECTED>
//	TIMESTAMP: <last-change-time>
//
// The file is updated whenever wpa_supplicant reports a change of the 802.1X
// authentication state, including every (re-)authentication, which the network
// monitor picks up through inotify. The events are received by attaching
// directly to the control socket of wpa_supplicant. It blocks until the context
// is canceled, re-attaching whenever the connection is lost.
func (c *WpaSupplicantConfigurator) watchPNACEvents(ctx context.Context, ifName string) {
	ctrlPath := filepath.Join(types.WpaSupplicantCtrlSockDir, ifName)
	localPath := filepath.Join(nimRunDir, fmt.Sprintf("wpa_ctrl-%s-%d", ifName, os.Getpid()))
	tracker := newPNACStateTracker(pnacStateSettleDelay, func(state string) {
		c.writePNACStateFile(ifName, state, true)
	})
	defer tracker.stop()

	const retryDelay = 2 * time.Second
	for ctx.Err() == nil {
		// Attaching right after wpa_supplicant was started is expected to fail
		// until it creates the control socket.
		err := wpaEventListener(ctx, ctrlPath, localPath,
			func() { c.syncPNACStateFromSupplicant(ifName) },
			tracker.handleEvent)
		if err != nil {
			c.Log.Functionf("wpa_supplicant event listener for %s: %v", ifName, err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(retryDelay):
		}
	}
}

// Modify is not implemented.
func (c *WpaSupplicantConfigurator) Modify(ctx context.Context,
	oldItem, newItem depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete stops wpa_supplicant and removes the config file.
func (c *WpaSupplicantConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	s, ok := item.(WpaSupplicant)
	if !ok {
		return fmt.Errorf("invalid item type %T, expected WpaSupplicant", item)
	}

	pms := c.procManagers[s.AdapterIfName]
	delete(c.procManagers, s.AdapterIfName)

	done := reconciler.ContinueInBackground(ctx)
	go func() {
		if pms != nil && pms.stopWatcher != nil {
			// Stop delivering events first so that the shutdown of
			// wpa_supplicant is not reported as an authentication change.
			pms.stopWatcher()
			select {
			case <-pms.watcherDone:
			case <-time.After(wpaSupplicantStopTimeout):
				c.Log.Errorf("Timed out waiting for the wpa_supplicant event watcher "+
					"of %s to stop", s.AdapterIfName)
			}
		}

		// Without EAPOL-Logoff the authenticator keeps the port authorized
		// (e.g. in the post-authentication VLAN) after the supplicant is gone.
		if s.PNACConfig != nil {
			ctrlPath := filepath.Join(types.WpaSupplicantCtrlSockDir, s.AdapterIfName)
			localPath := filepath.Join(nimRunDir,
				fmt.Sprintf("wpa_ctrl-%s-%d-logoff", s.AdapterIfName, os.Getpid()))
			if err := wpaCtrlLogoff(ctrlPath, localPath); err != nil {
				c.Log.Warnf("Failed to send EAPOL-Logoff for %s: %v",
					s.AdapterIfName, err)
			}
		}

		// Stop wpa_supplicant itself.
		var err error
		if pms != nil && pms.supplicantPM != nil {
			ctx, cancel := context.WithTimeout(ctx, wpaSupplicantStopTimeout)
			err = pms.supplicantPM.Stop(ctx)
			cancel()
		}

		// Clean up all files created for this supplicant instance. Ignore errors.
		_ = os.Remove(c.configPath(s.AdapterIfName))
		if s.PNACConfig != nil {
			_ = os.Remove(c.pnacStatePath(s.AdapterIfName))
		}
		done(err)
	}()
	return nil
}

// NeedsRecreate returns true because Modify is not implemented.
func (c *WpaSupplicantConfigurator) NeedsRecreate(
	oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}

func (c *WpaSupplicantConfigurator) configPath(ifName string) string {
	return filepath.Join(nimRunDir, "wpa_supplicant-"+ifName+".conf")
}

func (c *WpaSupplicantConfigurator) pnacStatePath(ifName string) string {
	return filepath.Join(types.PNACStateDir, ifName)
}

// syncPNACStateFromSupplicant queries the current wpa_supplicant status and writes
// the PNAC state file if authentication has already completed. This closes the race
// window where wpa_supplicant finishes 802.1x authentication before the event
// listener attaches to it, causing the CONNECTED event to be missed.
func (c *WpaSupplicantConfigurator) syncPNACStateFromSupplicant(ifName string) {
	cmd := exec.Command("wpa_cli", "-p", types.WpaSupplicantCtrlSockDir,
		"-i", ifName, "status")
	outBytes, err := cmd.Output()
	if err != nil {
		c.Log.Warnf("Failed to query PNAC status for %s: %v",
			ifName, err)
		return
	}
	var paeState, suppPortStatus, eapState string
	for _, line := range strings.Split(string(outBytes), "\n") {
		fields := strings.SplitN(line, "=", 2)
		if len(fields) != 2 {
			continue
		}
		key, val := strings.TrimSpace(fields[0]), strings.TrimSpace(fields[1])
		switch key {
		case "Supplicant PAE state":
			paeState = val
		case "suppPortStatus":
			suppPortStatus = val
		case "EAP state":
			eapState = val
		}
	}
	if paeState == "AUTHENTICATED" &&
		suppPortStatus == "Authorized" &&
		eapState == "SUCCESS" {
		c.Log.Noticef("Interface %s is already authenticated, writing state file",
			ifName)
		c.writePNACStateFile(ifName, pnacStateConnected, false)
	}
}

// writePNACStateFile atomically writes the PNAC state file for the given interface.
// With replace=false the write is skipped (not an error) if the file already exists,
// which is checked with Renameat2 and RENAME_NOREPLACE to avoid a TOCTOU race with
// the event listener.
func (c *WpaSupplicantConfigurator) writePNACStateFile(ifName, state string, replace bool) {
	statePath := c.pnacStatePath(ifName)
	// Both kinds of writers use their own tmp file. The network monitor ignores
	// files with the .tmp extension.
	tmpPath := statePath + ".sync.tmp"
	if replace {
		tmpPath = statePath + ".event.tmp"
	}
	content := fmt.Sprintf("STATE: %s\nTIMESTAMP: %s\n",
		state, strconv.FormatInt(time.Now().Unix(), 10))
	if err := os.WriteFile(tmpPath, []byte(content), 0644); err != nil {
		c.Log.Errorf("Failed to write %s: %v", tmpPath, err)
		return
	}
	if replace {
		if err := os.Rename(tmpPath, statePath); err != nil {
			c.Log.Errorf("Failed to rename %s -> %s: %v", tmpPath, statePath, err)
			os.Remove(tmpPath)
		}
		return
	}
	stateDir := filepath.Dir(statePath)
	stateFile := filepath.Base(statePath)
	tmpFile := filepath.Base(tmpPath)
	dirFD, err := unix.Open(stateDir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		c.Log.Errorf("Failed to open dir %s: %v", stateDir, err)
		os.Remove(tmpPath)
		return
	}
	defer unix.Close(dirFD)
	err = unix.Renameat2(dirFD, tmpFile, dirFD, stateFile, unix.RENAME_NOREPLACE)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			c.Log.Noticef(
				"PNAC state file for %s already exists, event listener got there first",
				ifName)
		} else {
			c.Log.Errorf("renameat2 %s -> %s failed: %v", tmpPath, statePath, err)
		}
		os.Remove(tmpPath)
	}
}

func (c *WpaSupplicantConfigurator) createConfigFile(s WpaSupplicant) error {
	cfgPath := c.configPath(s.AdapterIfName)
	file, err := os.Create(cfgPath)
	if err != nil {
		err = fmt.Errorf("failed to create wpa_supplicant config %s: %w", cfgPath, err)
		c.Log.Error(err)
		return err
	}
	defer file.Close()

	var cfg string
	switch {
	case len(s.WiFiConfigs) > 0:
		cfg = c.renderWifiConfig(s.WiFiConfigs)
	case s.PNACConfig != nil:
		cfg = c.renderPNACConfig(*s.PNACConfig)
	default:
		return fmt.Errorf("wpa_supplicant has no configuration")
	}

	if _, err := file.WriteString(cfg); err != nil {
		err = fmt.Errorf("failed to write wpa_supplicant config %s: %w", cfgPath, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *WpaSupplicantConfigurator) renderWifiConfig(cfgs []WifiConfig) string {
	var b strings.Builder

	b.WriteString("# Automatically generated by NIM\n")
	fmt.Fprintf(&b, "ctrl_interface=%s\n", types.WpaSupplicantCtrlSockDir)
	b.WriteString("ap_scan=1\n\n")

	for _, cfg := range cfgs {
		b.WriteString("network={\n")
		fmt.Fprintf(&b, "    ssid=\"%s\"\n", cfg.SSID)
		b.WriteString("    scan_ssid=1\n")

		switch cfg.KeyScheme {
		case types.KeySchemeWpaPsk:
			b.WriteString("    key_mgmt=WPA-PSK\n")
			if cfg.PasswordHash != "" {
				fmt.Fprintf(&b, "    psk=%s\n", cfg.PasswordHash)
			}

		case types.KeySchemeWpaEap:
			b.WriteString("    key_mgmt=WPA-EAP\n")
			b.WriteString("    eap=PEAP\n")

			if cfg.Identity != "" {
				fmt.Fprintf(&b, "    identity=\"%s\"\n", cfg.Identity)
			}
			if cfg.PasswordHash != "" {
				fmt.Fprintf(&b, "    password=hash:%s\n", cfg.PasswordHash)
			}

			b.WriteString("    phase1=\"peaplabel=1\"\n")
			b.WriteString("    phase2=\"auth=MSCHAPV2\"\n")
		}

		if cfg.Priority != 0 {
			fmt.Fprintf(&b, "    priority=%d\n", cfg.Priority)
		}
		b.WriteString("}\n\n")
	}

	return b.String()
}

func (c *WpaSupplicantConfigurator) renderPNACConfig(cfg PNAC8021XConfig) string {
	return fmt.Sprintf(`# Automatically generated by NIM
ctrl_interface=%s
ap_scan=0

network={
    key_mgmt=IEEE8021X
    eap=TLS
    eapol_flags=0
    identity="%s"
    ca_cert="%s"
    client_cert="%s"
    private_key="%s"
}
`,
		types.WpaSupplicantCtrlSockDir,
		cfg.EAPIdentity,
		cfg.CACertBundlePath,
		cfg.ClientCertPath,
		cfg.ClientKeyPath,
	)
}
