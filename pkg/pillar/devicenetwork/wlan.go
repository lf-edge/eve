// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	wpaFilename = "/run/wlan/wpa_supplicant.conf" // wifi wpa_supplicant file, currently only support one
	runwlanDir  = "/run/wlan"
	wpaTempname = "wpa_supplicant.temp"
)

func updateWlanConfig(ctx *DeviceNetworkContext, oldCfg *types.DevicePortConfig, newCfg *types.DevicePortConfig) (err error) {
	log := ctx.Log
	log.Functionf("updateWlanConfig: oldCfg.Key=%v, oldCfg-nil=%v, portCfg.Ports=%v\n",
		newCfg.Key, oldCfg == nil, newCfg.Ports)
	var hasWifiPortConfig bool

	for _, portCfg := range oldCfg.Ports {
		if portCfg.WirelessCfg.WType != types.WirelessTypeWifi {
			continue
		}
		if newCfg.LookupPortByIfName(portCfg.IfName) == nil {
			// clear previously installed wpa file
			err = devPortInstallWifiConfig(ctx, portCfg.IfName, types.WirelessConfig{})
			if err != nil {
				log.Errorf("updateWlanConfig: failed to install WiFi config: %v\n", err)
				return err
			}
		}
	}
	for _, portCfg := range newCfg.Ports {
		if portCfg.WirelessCfg.WType != types.WirelessTypeWifi {
			continue
		}
		hasWifiPortConfig = true
		oldPortCfg := oldCfg.LookupPortByIfName(portCfg.IfName)
		if oldPortCfg == nil || !reflect.DeepEqual(oldPortCfg.WirelessCfg, portCfg.WirelessCfg) {
			err = devPortInstallWifiConfig(ctx, portCfg.IfName, portCfg.WirelessCfg)
			if err != nil {
				log.Errorf("updateWlanConfig: failed to install WiFi config: %v\n", err)
				return err
			}
		}
	}
	return toggleWlanRF(ctx.Log, !ctx.RadioSilence.Imposed && hasWifiPortConfig)
}

func hasWifiPortConfig(ctx *DeviceNetworkContext) bool {
	dpc := ctx.DevicePortConfig
	if ctx.Pending.Inprogress {
		dpc = &ctx.Pending.PendDPC
	}
	for _, portCfg := range dpc.Ports {
		if portCfg.WirelessCfg.WType == types.WirelessTypeWifi {
			return true
		}
	}
	return false
}

func devPortInstallWifiConfig(ctx *DeviceNetworkContext,
	ifname string, wconfig types.WirelessConfig) error {

	log := ctx.Log
	if _, err := os.Stat(runwlanDir); os.IsNotExist(err) {
		err = os.Mkdir(runwlanDir, 600)
		if err != nil {
			err = fmt.Errorf("Failed to create directory %s: %v\n", runwlanDir, err)
			log.Error(err)
			return err
		}
	}

	tmpfile, err := ioutil.TempFile(runwlanDir, wpaTempname)
	if err != nil {
		err = fmt.Errorf("Failed to create temporary file %s/%s: %v\n",
			runwlanDir, wpaTempname, err)
		log.Error(err)
		return err
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	tmpfile.Chmod(0600)

	log.Functionf("devPortInstallWifiConfig: write file %s for wifi params %v, size %d",
		wpaFilename, wconfig.Wifi, len(wconfig.Wifi))
	if len(wconfig.Wifi) == 0 {
		// generate dummy wpa_supplicant.conf
		tmpfile.WriteString("# Fill in the networks and their passwords\nnetwork={\n")
		tmpfile.WriteString("       ssid=\"XXX\"\n")
		tmpfile.WriteString("       scan_ssid=1\n")
		tmpfile.WriteString("       key_mgmt=WPA-PSK\n")
		tmpfile.WriteString("       psk=\"YYYYYYYY\"\n")
		tmpfile.WriteString("}\n")
	} else {
		tmpfile.WriteString("# Automatically generated\n")
		for _, wifi := range wconfig.Wifi {
			decBlock, err := getWifiCredential(ctx, wifi)
			if err != nil {
				continue
			}
			tmpfile.WriteString("network={\n")
			s := fmt.Sprintf("        ssid=\"%s\"\n", wifi.SSID)
			tmpfile.WriteString(s)
			tmpfile.WriteString("        scan_ssid=1\n")
			switch wifi.KeyScheme {
			case types.KeySchemeWpaPsk: // WPA-PSK
				tmpfile.WriteString("        key_mgmt=WPA-PSK\n")
				// this assumes a hashed passphrase, otherwise need "" around string
				if len(decBlock.WifiPassword) > 0 {
					s = fmt.Sprintf("        psk=%s\n", decBlock.WifiPassword)
					tmpfile.WriteString(s)
				}
			case types.KeySchemeWpaEap: // EAP PEAP
				tmpfile.WriteString("        key_mgmt=WPA-EAP\n        eap=PEAP\n")
				if len(decBlock.WifiUserName) > 0 {
					s = fmt.Sprintf("        identity=\"%s\"\n", decBlock.WifiUserName)
					tmpfile.WriteString(s)
				}
				if len(decBlock.WifiPassword) > 0 {
					s = fmt.Sprintf("        password=hash:%s\n", decBlock.WifiPassword)
					tmpfile.WriteString(s)
				}
				// comment out the certifacation verify. file.WriteString("        ca_cert=\"/config/ca.pem\"\n")
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
	tmpfile.Sync()
	if err := tmpfile.Close(); err != nil {
		err = fmt.Errorf("Failed to close temporary file %s: %v\n",
			tmpfile.Name(), err)
		log.Error(err)
		return err
	}

	if err := os.Rename(tmpfile.Name(), wpaFilename); err != nil {
		err = fmt.Errorf("Failed to rename file %s to %s: %v\n",
			tmpfile.Name(), wpaFilename, err)
		log.Error(err)
		return err
	}
	log.Functionf("devPortInstallWifiConfig: updated wpa file for interface '%s'\n", ifname)
	return nil
}

func getWifiCredential(ctx *DeviceNetworkContext,
	wifi types.WifiConfig) (types.EncryptionBlock, error) {

	log := ctx.Log
	if wifi.CipherBlockStatus.IsCipher {
		status, decBlock, err := cipher.GetCipherCredentials(&ctx.DecryptCipherContext,
			wifi.CipherBlockStatus)
		ctx.PubCipherBlockStatus.Publish(status.Key(), status)
		if err != nil {
			log.Errorf("%s, wifi config cipherblock decryption unsuccessful, falling back to cleartext: %v\n",
				wifi.SSID, err)
			decBlock.WifiUserName = wifi.Identity
			decBlock.WifiPassword = wifi.Password
			// We assume IsCipher is only set when there was some
			// data. Hence this is a fallback if there is
			// some cleartext.
			if decBlock.WifiUserName != "" || decBlock.WifiPassword != "" {
				cipher.RecordFailure(ctx.Log, ctx.AgentName,
					types.CleartextFallback)
			} else {
				cipher.RecordFailure(ctx.Log, ctx.AgentName,
					types.MissingFallback)
			}
			return decBlock, nil
		}
		log.Functionf("%s, wifi config cipherblock decryption successful\n", wifi.SSID)
		return decBlock, nil
	}
	log.Functionf("%s, wifi config cipherblock not present\n", wifi.SSID)
	decBlock := types.EncryptionBlock{}
	decBlock.WifiUserName = wifi.Identity
	decBlock.WifiPassword = wifi.Password
	if decBlock.WifiUserName != "" || decBlock.WifiPassword != "" {
		cipher.RecordFailure(ctx.Log, ctx.AgentName, types.NoCipher)
	} else {
		cipher.RecordFailure(ctx.Log, ctx.AgentName, types.NoData)
	}
	return decBlock, nil
}

// Enable or disable all WLAN radio devices.
// Note that for WLAN devices we cannot control RF separately for each adapter (like we do for cellular modems).
// We can either enable or disable all of them at the same time. This means that if radio silence is turned off
// (wireless devices are allowed), then even if only a subset of WiFi adapters have configuration,
// all WiFi adapters will be actually enabled.
func toggleWlanRF(log *base.LogObject, enableRF bool) error {
	op := "block"
	if enableRF {
		op = "un" + op
	}
	args := []string{op, "wlan"}
	log.Noticef("Running rfkill %v", args)
	out, err := base.Exec(log, "rfkill", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("'rfkill %s' command failed with err=%v, output=%s",
			strings.Join(args, " "), err, out)
	}
	return nil
}
