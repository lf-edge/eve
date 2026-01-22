// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/proc"
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

	// Path to the trusted CA certificate used to validate the authentication server.
	CACertPath string

	// Path to the client certificate used for EAP-TLS authentication.
	ClientCertPath string

	// Path to the client private key used for EAP-TLS authentication.
	// Exactly one of ClientKeyPath or TPMClientKey must be configured.
	ClientKeyPath string

	// Reference to a TPM-resident private key used for EAP-TLS authentication.
	// Mutually exclusive with ClientKeyPath.
	TPMClientKey *TPMClientKey
}

// Equal is a comparison method for PNAC8021XConfig.
func (c *PNAC8021XConfig) Equal(other *PNAC8021XConfig) bool {
	if c == nil || other == nil {
		return c == other
	}
	return c.EAPIdentity == other.EAPIdentity &&
		c.CACertPath == other.CACertPath &&
		c.ClientCertPath == other.ClientCertPath &&
		c.ClientKeyPath == other.ClientKeyPath &&
		c.TPMClientKey.Equal(other.TPMClientKey)
}

// String returns human-readable PNAC8021XConfig description.
func (c *PNAC8021XConfig) String() string {
	if c == nil {
		return "<nil>"
	}
	keySrc := "file"
	if c.TPMClientKey != nil {
		keySrc = "TPM"
	}
	return fmt.Sprintf("EAPIdentity=%q, CACert=%q, ClientCert=%q, KeySource=%s",
		c.EAPIdentity, c.CACertPath, c.ClientCertPath, keySrc)
}

// TPMClientKey represents a TPM-resident private key referenced via a PKCS#11 URI.
// Used for EAP-TLS authentication without exposing private key material to userspace.
type TPMClientKey struct {
	// TokenLabel identifies the TPM-backed PKCS#11 token.
	TokenLabel string

	// ObjectLabel identifies the private key object within the token.
	ObjectLabel string

	// PIN is the authentication value required to access the token.
	PIN string
}

// Equal is a comparison method for TPMClientKey.
func (k *TPMClientKey) Equal(other *TPMClientKey) bool {
	if k == nil || other == nil {
		return k == other
	}
	return *k == *other
}

// String returns human-readable TPMClientKey description without the sensitive PIN.
func (k *TPMClientKey) String() string {
	if k == nil {
		return "<nil>"
	}
	return fmt.Sprintf("TokenLabel=%q, ObjectLabel=%q", k.TokenLabel, k.ObjectLabel)
}

// PKCS11URI returns the full PKCS#11 URI for the TPM-resident private key.
func (k *TPMClientKey) PKCS11URI() string {
	if k == nil {
		return "<nil>"
	}
	return fmt.Sprintf("pkcs11:token=%s;object=%s?pin-value=%s",
		k.TokenLabel, k.ObjectLabel, k.PIN)
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

// Dependencies lists the adapter as the only dependency of the wpa_supplicant.
func (s WpaSupplicant) Dependencies() (deps []depgraph.Dependency) {
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: AdapterTypename,
				ItemName: s.AdapterIfName,
			},
			Description: "Network adapter must exist",
		},
	}
}

// WpaSupplicantConfigurator implements Configurator interface (libs/reconciler)
// for WpaSupplicant.
type WpaSupplicantConfigurator struct {
	Log *base.LogObject
}

// Create prepares config file and starts wpa_supplicant.
func (c *WpaSupplicantConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	s, ok := item.(WpaSupplicant)
	if !ok {
		return fmt.Errorf("invalid item type %T, expected WpaSupplicant", item)
	}

	if err := c.createConfigFile(s); err != nil {
		return err
	}

	done := reconciler.ContinueInBackground(ctx)
	go func() {
		pm := c.initProcessManager(s)
		ctx, cancel := context.WithTimeout(ctx, wpaSupplicantStartTimeout)
		defer cancel()
		err := pm.Start(ctx)
		done(err)
	}()
	return nil
}

func (c *WpaSupplicantConfigurator) initProcessManager(
	s WpaSupplicant) proc.ProcessManager {
	pidFile := c.pidFilePath(s.AdapterIfName)

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
		"-P", pidFile,
		"-d",         // increase debugging verbosity
		"-B",         // daemonize
		"-D", driver, // explicitly set driver
	}
	return proc.ProcessManager{
		Log:       c.Log,
		PidFile:   pidFile,
		Cmd:       "wpa_supplicant",
		Args:      args,
		WithNohup: true,
		WillFork:  true,
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

	done := reconciler.ContinueInBackground(ctx)
	go func() {
		pm := c.initProcessManager(s)
		ctx, cancel := context.WithTimeout(ctx, wpaSupplicantStopTimeout)
		defer cancel()
		err := pm.Stop(ctx)
		if err == nil {
			_ = os.Remove(c.configPath(s.AdapterIfName))
			_ = os.Remove(c.pidFilePath(s.AdapterIfName))
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
	return filepath.Join(nimRunDir, "wpa_supplicant."+ifName+".conf")
}

func (c *WpaSupplicantConfigurator) pidFilePath(ifName string) string {
	return filepath.Join(nimRunDir, "wpa_supplicant."+ifName+".pid")
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
	fmt.Fprintf(&b, "ctrl_interface=%s/wpa_supplicant\n", nimRunDir)
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
	var privateKey string
	if cfg.TPMClientKey != nil {
		privateKey = cfg.TPMClientKey.PKCS11URI()
	} else {
		privateKey = cfg.ClientKeyPath
	}

	return fmt.Sprintf(`# Automatically generated by NIM
ctrl_interface=%s/wpa_supplicant
ap_scan=0

network={
    key_mgmt=IEEE8021X
    eap=TLS
    eapol_flags=0
    identity="%s"
    ca_cert="%s"
    client_cert="%s"
    private_key=%s
}
`,
		nimRunDir,
		cfg.EAPIdentity,
		cfg.CACertPath,
		cfg.ClientCertPath,
		privateKey,
	)
}
