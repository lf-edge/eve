// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Wlan : WLAN (WiFi) configuration (for WPA supplicant and rfkill).
// Note that currently only one WiFi adapter per device is supported.
type Wlan struct {
	Config []WifiConfig
	// EnableRF : Enable or disable radio transmission.
	EnableRF bool
}

// WifiConfig : WiFi configuration.
type WifiConfig struct {
	types.WifiConfig
	Credentials types.EncryptionBlock
}

// String describes WifiConfig without revealing any sensitive info.
func (wc WifiConfig) String() string {
	return fmt.Sprintf("WifiConfig: {SSID: %s, KeyScheme: %d, "+
		"Identity: %s, Priority: %d}", wc.SSID, wc.KeyScheme, wc.Identity, wc.Priority)
}

// Name returns the wpa_supplicant.conf file path as the name.
func (w Wlan) Name() string {
	return devicenetwork.WpaFilename
}

// Label is not defined.
func (w Wlan) Label() string {
	return ""
}

// Type of the item.
func (w Wlan) Type() string {
	return genericitems.WlanTypename
}

// Equal compares two WLAN configurations.
func (w Wlan) Equal(other depgraph.Item) bool {
	w2 := other.(Wlan)
	return reflect.DeepEqual(w.Config, w2.Config) &&
		w.EnableRF == w2.EnableRF
}

// External returns false.
func (w Wlan) External() bool {
	return false
}

// String describes the WLAN configuration.
func (w Wlan) String() string {
	return fmt.Sprintf("WLAN configuration: %v, enable RF: %t",
		w.Config, w.EnableRF)
}

// Dependencies returns nothing.
// Configurator for this config item only installs wpa_supplicant.conf
// and that has no dependencies.
func (w Wlan) Dependencies() (deps []depgraph.Dependency) {
	return nil
}

// WlanConfigurator implements Configurator interface (libs/reconciler) for wpa_supplicant.conf.
type WlanConfigurator struct {
	Log *base.LogObject
}

// Create installs wpa_supplicant.conf.
func (c *WlanConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	wlan := item.(Wlan)
	err := c.installWifiConfig(wlan.Config)
	if err != nil {
		return err
	}
	return c.toggleWlanRF(wlan.EnableRF)
}

// Modify updates the content of wpa_supplicant.conf.
func (c *WlanConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) error {
	wlan := newItem.(Wlan)
	err := c.installWifiConfig(wlan.Config)
	if err != nil {
		return err
	}
	return c.toggleWlanRF(wlan.EnableRF)
}

// Delete clears previously installed wpa file.
func (c *WlanConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	err := c.installWifiConfig([]WifiConfig{})
	if err != nil {
		return err
	}
	return c.toggleWlanRF(false)
}

// NeedsRecreate returns false - Modify can apply any change.
func (c *WlanConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return false
}

func (c *WlanConfigurator) installWifiConfig(config []WifiConfig) error {
	if _, err := os.Stat(devicenetwork.RunWlanDir); os.IsNotExist(err) {
		err = os.Mkdir(devicenetwork.RunWlanDir, 600)
		if err != nil {
			err = fmt.Errorf("failed to create directory %s: %v",
				devicenetwork.RunWlanDir, err)
			c.Log.Error(err)
			return err
		}
	}
	tmpfile, err := os.CreateTemp(devicenetwork.RunWlanDir, devicenetwork.WpaTempname)
	if err != nil {
		err = fmt.Errorf("failed to create temporary file %s/%s: %v",
			devicenetwork.RunWlanDir, devicenetwork.WpaTempname, err)
		c.Log.Error(err)
		return err
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	if err = tmpfile.Chmod(0600); err != nil {
		err = fmt.Errorf("failed to chmod temporary file %s: %v",
			tmpfile.Name(), err)
		c.Log.Error(err)
		return err
	}
	if len(config) == 0 {
		// generate dummy wpa_supplicant.conf
		tmpfile.WriteString("# No WiFi config received\n")
	} else {
		tmpfile.WriteString("# Automatically generated\n")
		for _, wifi := range config {
			tmpfile.WriteString("network={\n")
			s := fmt.Sprintf("        ssid=\"%s\"\n", wifi.SSID)
			tmpfile.WriteString(s)
			tmpfile.WriteString("        scan_ssid=1\n")
			switch wifi.KeyScheme {
			case types.KeySchemeWpaPsk: // WPA-PSK
				tmpfile.WriteString("        key_mgmt=WPA-PSK\n")
				// this assumes a hashed passphrase, otherwise need "" around string
				if len(wifi.Credentials.WifiPassword) > 0 {
					s = fmt.Sprintf("        psk=%s\n",
						wifi.Credentials.WifiPassword)
					tmpfile.WriteString(s)
				}
			case types.KeySchemeWpaEap: // EAP PEAP
				tmpfile.WriteString("        key_mgmt=WPA-EAP\n        eap=PEAP\n")
				if len(wifi.Credentials.WifiUserName) > 0 {
					s = fmt.Sprintf("        identity=\"%s\"\n",
						wifi.Credentials.WifiUserName)
					tmpfile.WriteString(s)
				}
				if len(wifi.Credentials.WifiPassword) > 0 {
					s = fmt.Sprintf("        password=hash:%s\n",
						wifi.Credentials.WifiPassword)
					tmpfile.WriteString(s)
				}
				// comment out the cert verification.
				// file.WriteString("        ca_cert=\"/config/ca.pem\"\n")
				tmpfile.WriteString("        phase1=\"peaplabel=1\"\n")
				tmpfile.WriteString("        phase2=\"auth=MSCHAPV2\"\n")
			}
			if wifi.Priority != 0 {
				s = fmt.Sprintf("        priority=%d\n", wifi.Priority)
				tmpfile.WriteString(s)
			}
			tmpfile.WriteString("}\n")
		}
	}
	if err = tmpfile.Sync(); err != nil {
		err = fmt.Errorf("failed to sync temporary file %s: %v\n",
			tmpfile.Name(), err)
		c.Log.Error(err)
		return err
	}
	if err = tmpfile.Close(); err != nil {
		err = fmt.Errorf("failed to close temporary file %s: %v\n",
			tmpfile.Name(), err)
		c.Log.Error(err)
		return err
	}
	if err := os.Rename(tmpfile.Name(), devicenetwork.WpaFilename); err != nil {
		err = fmt.Errorf("failed to rename file %s to %s: %v\n",
			tmpfile.Name(), devicenetwork.WpaFilename, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

// Enable or disable all WLAN radio devices.
// Note that for WLAN devices we cannot control RF separately for each adapter (like we do for cellular modems).
// We can either enable or disable all of them at the same time. This means that if radio silence is turned off
// (wireless devices are allowed), then even if only a subset of WiFi adapters have configuration,
// all WiFi adapters will be actually enabled.
func (c *WlanConfigurator) toggleWlanRF(enableRF bool) error {
	op := "block"
	if enableRF {
		op = "un" + op
	}
	args := []string{op, "wlan"}
	c.Log.Noticef("Running rfkill %v", args)
	out, err := base.Exec(c.Log, "rfkill", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("'rfkill %s' command failed with err=%v, output=%s",
			strings.Join(args, " "), err, out)
	}
	return nil
}
