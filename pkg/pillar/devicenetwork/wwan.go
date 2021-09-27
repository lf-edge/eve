// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	runWwanDir      = "/run/wwan/"
	wwanConfigPath  = runWwanDir + "config.json"
	wwanStatusPath  = runWwanDir + "status.json"
	wwanMetricsPath = runWwanDir + "metrics.json"
)

// WwanService encapsulates data exchanged between nim and the wwan service.
type WwanService struct {
	ConfigChecksum string
	Config         types.WwanConfig
	Status         types.WwanStatus
	Metrics        types.WwanMetrics
}

// InitWwanWatcher starts to watch for state data and metrics published by the wwan service.
func InitWwanWatcher(log *base.LogObject) (*fsnotify.Watcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		err = fmt.Errorf("failed to create wwan watcher: %w", err)
		log.Error(err)
		return nil, err
	}

	if err = createWwanDir(log); err != nil {
		return nil, err
	}
	if err = w.Add(runWwanDir); err != nil {
		_ = w.Close()
		return nil, err
	}
	return w, nil
}

// ProcessWwanWatchEvent processes change in the wwan status data or metrics.
func ProcessWwanWatchEvent(ctx *DeviceNetworkContext, event fsnotify.Event) {
	switch event.Name {
	case wwanStatusPath:
		ReloadWwanStatus(ctx)
	case wwanMetricsPath:
		ReloadWwanMetrics(ctx)
	}
}

// ReloadWwanStatus loads the latest state data published by the wwan service.
func ReloadWwanStatus(ctx *DeviceNetworkContext) {
	log := ctx.Log
	statusFile, err := os.Open(wwanStatusPath)
	if err != nil {
		log.Errorf("Failed to open file %s: %v", wwanStatusPath, err)
		return
	}
	defer statusFile.Close()

	statusBytes, err := ioutil.ReadAll(statusFile)
	if err != nil {
		log.Errorf("Failed to read file %s: %v", wwanStatusPath, err)
		return
	}

	var status types.WwanStatus
	err = json.Unmarshal(statusBytes, &status)
	if err != nil {
		log.Errorf("Failed to unmarshall wwan status: %v", err)
		return
	}
	expectedChecksum := ctx.WwanService.ConfigChecksum
	if expectedChecksum != "" && expectedChecksum != status.ConfigChecksum {
		log.Noticef("Ignoring obsolete wwan status")
		return
	}

	status.DoSanitize()
	if reflect.DeepEqual(status, ctx.WwanService.Status) {
		// nothing really changed
		return
	}

	netName := func(modem types.WwanNetworkStatus) string {
		netName := modem.LogicalLabel
		if netName == "" {
			netName = modem.PhysAddrs.Interface
		}
		return netName
	}

	ctx.WwanService.Status = status
	log.Functionf("Have new wwan status: %v", ctx.WwanService.Status)
	if ctx.RadioSilence.ChangeInProgress {
		var errMsgs []string
		if ctx.RadioSilence.ConfigError != "" {
			errMsgs = append(errMsgs, ctx.RadioSilence.ConfigError)
		}
		for _, network := range status.Networks {
			if network.ConfigError != "" {
				errMsgs = append(errMsgs, netName(network)+": "+network.ConfigError)
			}
		}
		if ctx.RadioSilence.Imposed {
			for _, network := range status.Networks {
				if network.Module.OpMode != types.WwanOpModeRadioOff {
					// Failed to turn off the radio
					log.Warnf("Modem %s (network: %s) is not in the radio-off operational state",
						network.Module.Name, netName(network))
					ctx.RadioSilence.Imposed = false // the actual state
					if network.ConfigError == "" {
						errMsgs = append(errMsgs,
							fmt.Sprintf("%s: modem %s is not in the radio-off operational state",
								netName(network), network.Module.Name))
					}
				}
			}
		}
		ctx.RadioSilence.ConfigError = strings.Join(errMsgs, "\n")
		ctx.RadioSilence.ChangeInProgress = false
		log.Noticeln("Radio-silence state changing operation has finalized (as seen by nim)")
	}

	if !ctx.Pending.Inprogress {
		newDNS := MakeDeviceNetworkStatus(ctx, *ctx.DevicePortConfig, *ctx.DeviceNetworkStatus)
		ctx.DeviceNetworkStatus = &newDNS
		if ctx.PubDeviceNetworkStatus != nil {
			log.Functionf("PublishDeviceNetworkStatus: %+v",
				ctx.DeviceNetworkStatus)
			ctx.PubDeviceNetworkStatus.Publish("global",
				*ctx.DeviceNetworkStatus)
		}
	}
}

// ReloadWwanMetrics loads the latest metrics published by the wwan service.
func ReloadWwanMetrics(ctx *DeviceNetworkContext) {
	log := ctx.Log
	metricsFile, err := os.Open(wwanMetricsPath)
	if err != nil {
		log.Errorf("Failed to open file %s: %v", wwanMetricsPath, err)
		return
	}
	defer metricsFile.Close()

	var metrics types.WwanMetrics
	metricsBytes, err := ioutil.ReadAll(metricsFile)
	if err != nil {
		log.Errorf("Failed to read file %s: %v", wwanMetricsPath, err)
		return
	}

	err = json.Unmarshal(metricsBytes, &metrics)
	if err != nil {
		log.Errorf("Failed to unmarshall wwan metrics: %v", err)
		return
	}

	if reflect.DeepEqual(metrics, ctx.WwanService.Metrics) {
		// nothing really changed
		return
	}

	ctx.WwanService.Metrics = metrics
	if ctx.PubWwanMetrics != nil {
		log.Functionf("PubWwanMetrics: %+v", metrics)
		ctx.PubWwanMetrics.Publish("global", metrics)
	}
}

func updateWwanConfig(ctx *DeviceNetworkContext, portCfg *types.DevicePortConfig) (err error) {
	log := ctx.Log
	log.Functionf("updateWwanConfig: portCfg.Ports=%v", portCfg.Ports)

	newConfig := makeWwanConfig(ctx, portCfg)
	if !ctx.WwanService.Config.Equal(newConfig) {
		ctx.WwanService.Config = newConfig
		ctx.WwanService.ConfigChecksum, err = installWwanConfig(ctx.Log, ctx.WwanService.Config)
		return err
	}
	return nil
}

func makeWwanConfig(ctx *DeviceNetworkContext, portCfg *types.DevicePortConfig) types.WwanConfig {
	log := ctx.Log
	config := types.WwanConfig{RadioSilence: ctx.RadioSilence.Imposed, Networks: []types.WwanNetworkConfig{}}
	if portCfg == nil {
		return config
	}

	for _, port := range portCfg.Ports {
		if port.WirelessCfg.WType != types.WirelessTypeCellular || len(port.WirelessCfg.Cellular) == 0 {
			continue
		}
		ioBundle := ctx.AssignableAdapters.LookupIoBundleLogicallabel(port.Logicallabel)
		if ioBundle == nil {
			log.Warnf("Failed to find adapter with logical label '%s'", port.Logicallabel)
			continue
		}
		if ioBundle.IsPCIBack {
			log.Warnf("wwan adapter with the logical label '%s' is assigned to pciback, skipping",
				port.Logicallabel)
			continue
		}
		// XXX Limited to a single APN for now
		cellCfg := port.WirelessCfg.Cellular[0]
		network := types.WwanNetworkConfig{
			LogicalLabel: port.Logicallabel,
			PhysAddrs: types.WwanPhysAddrs{
				Interface: ioBundle.Ifname,
				USB:       ioBundle.UsbAddr,
				PCI:       ioBundle.PciLong,
			},
			Apns: []string{cellCfg.APN},
			Probe: types.WwanProbe{
				Disable: cellCfg.DisableProbe,
				Address: cellCfg.ProbeAddr,
			},
		}
		config.Networks = append(config.Networks, network)
	}
	return config
}

func createWwanDir(log *base.LogObject) error {
	if _, err := os.Stat(runWwanDir); err != nil {
		if err = os.MkdirAll(runWwanDir, 0700); err != nil {
			err = fmt.Errorf("failed to create directory %s: %w", runWwanDir, err)
			log.Error(err)
			return err
		}
	}
	return nil
}

// Write cellular config into /run/wwan/config.json
func installWwanConfig(log *base.LogObject, config types.WwanConfig) (checksum string, err error) {
	if err = createWwanDir(log); err != nil {
		return "", err
	}

	log.Noticef("installWwanConfig: write file %s with config %+v", wwanConfigPath, config)
	file, err := os.Create(wwanConfigPath)
	if err != nil {
		err = fmt.Errorf("failed to create file %s: %w", wwanConfigPath, err)
		log.Error(err)
		return "", err
	}
	defer file.Close()
	b, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		err = fmt.Errorf("failed to serialize wwan config: %w", err)
		log.Error(err)
		return "", err
	}
	if r, err := file.Write(b); err != nil || r != len(b) {
		err = fmt.Errorf("failed to write %d bytes to file %s: %w", len(b), file.Name(), err)
		log.Error(err)
		return "", err
	}

	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:]), nil
}

// react to changed radio-silence configuration
func updateRadioSilence(ctx *DeviceNetworkContext, radioSilence types.RadioSilence) {
	var err error
	var errMsgs []string
	log := ctx.Log
	ctx.RadioSilence = radioSilence

	// (asynchronously) update RF state for wwan
	ctx.WwanService.Config.RadioSilence = radioSilence.Imposed
	ctx.WwanService.ConfigChecksum, err = installWwanConfig(ctx.Log, ctx.WwanService.Config)
	if err != nil {
		errMsgs = append(errMsgs, fmt.Sprintf("Failed to install wwan config: %v", err))
		if ctx.RadioSilence.Imposed {
			// failed to disable wwan RF (can't even install config for wwan service)
			ctx.RadioSilence.Imposed = false
		}
	} else {
		ctx.RadioSilence.ChangeInProgress = true
		log.Noticef("Triggering radio-silence state change to: %s", ctx.RadioSilence)
	}

	// (synchronously) update rf state for wlan
	err = toggleWlanRF(log, !radioSilence.Imposed && hasWifiPortConfig(ctx))
	if err != nil {
		if ctx.RadioSilence.Imposed {
			// failed to disable wlan RF
			ctx.RadioSilence.Imposed = false
		}
		errMsgs = append(errMsgs, err.Error())
	}

	ctx.RadioSilence.ConfigError = strings.Join(errMsgs, "\n")
	if !ctx.Pending.Inprogress {
		ctx.DeviceNetworkStatus.RadioSilence = ctx.RadioSilence
		if ctx.PubDeviceNetworkStatus != nil {
			log.Functionf("PublishDeviceNetworkStatus: %+v\n",
				ctx.DeviceNetworkStatus)
			ctx.PubDeviceNetworkStatus.Publish("global",
				*ctx.DeviceNetworkStatus)
		}
	}
}
