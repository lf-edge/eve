// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cast

import (
	"encoding/json"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// XXX template?
// XXX alternative seems to be a deep copy of some sort

func CastNetworkXObjectConfig(in interface{}) types.NetworkXObjectConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastNetworkXObjectConfig")
	}
	var output types.NetworkXObjectConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastNetworkXObjectConfig")
	}
	return output
}

func CastNetworkInstanceConfig(in interface{}) types.NetworkInstanceConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "CastNetworkInstanceConfig: json Marshal error")
	}
	var output types.NetworkInstanceConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "CastNetworkInstanceConfig: json Unmarshal error")
	}
	return output
}

func CastNetworkInstanceStatus(in interface{}) types.NetworkInstanceStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "CastNetworkInstanceStatus: json Marshal error")
	}
	var output types.NetworkInstanceStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "CastNetworkInstanceStatus: json Unmarshal error")
	}
	return output
}

func CastNetworkInstanceMetrics(in interface{}) types.NetworkInstanceMetrics {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastNetworkInstanceMetrics")
	}
	var output types.NetworkInstanceMetrics
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastNetworkInstanceSMetrics")
	}
	return output
}

func CastDevicePortConfig(in interface{}) types.DevicePortConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastDevicePortConfig")
	}
	var output types.DevicePortConfig
	if err := json.Unmarshal(b, &output); err != nil {
		// Comes from outside sources like USB stick so don't Fatal
		log.Errorln(err, "json Unmarshal in CastDevicePortConfig")
	}
	return output
}

func CastDevicePortConfigList(in interface{}) types.DevicePortConfigList {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastDevicePortConfigList")
	}
	var output types.DevicePortConfigList
	if err := json.Unmarshal(b, &output); err != nil {
		// Comes from outside sources like USB stick so don't Fatal
		log.Errorln(err, "json Unmarshal in CastDevicePortConfigList")
	}
	return output
}

func CastDeviceNetworkStatus(in interface{}) types.DeviceNetworkStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastDeviceNetworkStatus")
	}
	var output types.DeviceNetworkStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastDeviceNetworkStatus")
	}
	return output
}

func CastAppInstanceConfig(in interface{}) types.AppInstanceConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastAppInstanceConfig")
	}
	var output types.AppInstanceConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastAppInstanceConfig")
	}
	return output
}

func CastAppInstanceStatus(in interface{}) types.AppInstanceStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastAppInstanceStatus")
	}
	var output types.AppInstanceStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastAppInstanceStatus")
	}
	return output
}

func CastAppNetworkConfig(in interface{}) types.AppNetworkConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastAppNetworkConfig")
	}
	var output types.AppNetworkConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastAppNetworkConfig")
	}
	return output
}

func CastAppNetworkStatus(in interface{}) types.AppNetworkStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastAppNetworkStatus")
	}
	var output types.AppNetworkStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastAppNetworkStatus")
	}
	return output
}

func CastDomainConfig(in interface{}) types.DomainConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastDomainConfig")
	}
	var output types.DomainConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastDomainConfig")
	}
	return output
}

func CastDomainStatus(in interface{}) types.DomainStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastDomainStatus")
	}
	var output types.DomainStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastDomainStatus")
	}
	return output
}

func CastEIDConfig(in interface{}) types.EIDConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastEIDConfig")
	}
	var output types.EIDConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastEIDConfig")
	}
	return output
}

func CastEIDStatus(in interface{}) types.EIDStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastEIDStatus")
	}
	var output types.EIDStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastEIDStatus")
	}
	return output
}

func CastCertObjConfig(in interface{}) types.CertObjConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastCertObjConfig")
	}
	var output types.CertObjConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastCertObjConfig")
	}
	return output
}

func CastCertObjStatus(in interface{}) types.CertObjStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastCertObjStatus")
	}
	var output types.CertObjStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastCertObjStatus")
	}
	return output
}

func CastBaseOsConfig(in interface{}) types.BaseOsConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastBaseOsConfig")
	}
	var output types.BaseOsConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastBaseOsConfig")
	}
	return output
}

func CastBaseOsStatus(in interface{}) types.BaseOsStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastBaseOsStatus")
	}
	var output types.BaseOsStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastBaseOsStatus")
	}
	return output
}

func CastDownloaderConfig(in interface{}) types.DownloaderConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastDownloaderConfig")
	}
	var output types.DownloaderConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastDownloaderConfig")
	}
	return output
}

func CastDownloaderStatus(in interface{}) types.DownloaderStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastDownloaderStatus")
	}
	var output types.DownloaderStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastDownloaderStatus")
	}
	return output
}

func CastVerifyImageConfig(in interface{}) types.VerifyImageConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastVerifyImageConfig")
	}
	var output types.VerifyImageConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastVerifyImageConfig")
	}
	return output
}

func CastVerifyImageStatus(in interface{}) types.VerifyImageStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastVerifyImageStatus")
	}
	var output types.VerifyImageStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastVerifyImageStatus")
	}
	return output
}

func CastAssignableAdapters(in interface{}) types.AssignableAdapters {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastAssignableAdapters")
	}
	var output types.AssignableAdapters
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastAssignableAdapters")
	}
	return output
}

func CastGlobalDownloadConfig(in interface{}) types.GlobalDownloadConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastGlobalDownloadConfig")
	}
	var output types.GlobalDownloadConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastGlobalDownloadConfig")
	}
	return output
}

func CastDatastoreConfig(in interface{}) types.DatastoreConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastDatastoreConfig")
	}
	var output types.DatastoreConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastDatastoreConfig")
	}
	return output
}

func CastLispDataplaneConfig(in interface{}) types.LispDataplaneConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastLispDataplaneConfig")
	}
	var output types.LispDataplaneConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastLispDataplaneConfig")
	}
	return output
}

func CastLispInfoStatus(in interface{}) types.LispInfoStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastLispInfoStatus")
	}
	var output types.LispInfoStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Error(err, "json Unmarshal in CastLispInfoStatus")
	}
	return output
}

func CastLispMetrics(in interface{}) types.LispMetrics {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastLispMetrics")
	}
	var output types.LispMetrics
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastLispMetrics")
	}
	return output
}

func CastGlobalConfig(in interface{}) types.GlobalConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastGlobalConfig")
	}
	var output types.GlobalConfig
	if err := json.Unmarshal(b, &output); err != nil {
		// File can be edited by hand. Don't Fatal
		log.Error(err, "json Unmarshal in CastGlobalConfig")
	}
	return output
}

func CastImageStatus(in interface{}) types.ImageStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastImageStatus")
	}
	var output types.ImageStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastImageStatus")
	}
	return output
}

func CastUuidToNum(in interface{}) types.UuidToNum {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastUuidToNum")
	}
	var output types.UuidToNum
	if err := json.Unmarshal(b, &output); err != nil {
		// File might be corrupted in /persist; don't fatal
		log.Error(err, "json Unmarshal in CastUuidToNum")
	}
	return output
}

// ZbootConfig : casts interface to ZbootConfig
func ZbootConfig(in interface{}) types.ZbootConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in ZbootConfig")
	}
	var output types.ZbootConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in ZbootConfig")
	}
	return output
}

// ZbootStatus : casts interface to ZbootStatus
func ZbootStatus(in interface{}) types.ZbootStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in ZbootStatus")
	}
	var output types.ZbootStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastZbootStatus")
	}
	return output
}

func CastLedBlinkCounter(in interface{}) types.LedBlinkCounter {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastLedBlinkCounter")
	}
	var output types.LedBlinkCounter
	if err := json.Unmarshal(b, &output); err != nil {
		// File might be corrupted in /var/tmp/zededa; don't fatal
		log.Error(err, "json Unmarshal in CastLedBlinkCounter")
	}
	return output
}

// CastFlowStatus : Cast interface type into types.IPFlow
func CastFlowStatus(in interface{}) types.IPFlow { //revive:disable-line
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatalf("json Marshal in CastFlowStats, %v", err)
	}
	var output types.IPFlow
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatalf("json Unmarshal in CastFlowStatus, %v", err)
	}
	return output
}

// CastPhysicalIOAdapterList : Cast interface type into
//       types.PhysicalIOAdapterList
func CastPhysicalIOAdapterList(in interface{}) types.PhysicalIOAdapterList { //revive:disable-line
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatalf("json Marshal in PhysicalIOAdapterList, %v", err)
	}
	var output types.PhysicalIOAdapterList
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatalf("json Unmarshal in CastPhysicalIOAdapterList, %v", err)
	}
	return output
}

// ZedAgentStatus : casts interface to ZedAgentStatus
func ZedAgentStatus(in interface{}) types.ZedAgentStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastZedAgentStatus")
	}
	var output types.ZedAgentStatus
	if err := json.Unmarshal(b, &output); err != nil {
		// File might be corrupted in /var/tmp/zededa; don't fatal
		log.Error(err, "json Unmarshal in CastZedAgentStatus")
	}
	return output
}

// NodeAgentStatus : casts interface to NodeAgentStatus
func NodeAgentStatus(in interface{}) types.NodeAgentStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastNodeAgentStatus")
	}
	var output types.NodeAgentStatus
	if err := json.Unmarshal(b, &output); err != nil {
		// File might be corrupted in /var/tmp/zededa; don't fatal
		log.Error(err, "json Unmarshal in CastNodeAgentStatus")
	}
	return output
}

// CastVaultStatus : Cast interface type into types.VaultStatus
func CastVaultStatus(in interface{}) types.VaultStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastVaultStatus")
	}
	var output types.VaultStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastVaultStatus")
	}
	return output
}
