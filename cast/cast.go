// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package cast

import (
	"encoding/json"

	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/types"
)

// XXX template?
// XXX alternative seems to be a deep copy of some sort

func CastNetworkObjectConfig(in interface{}) types.NetworkObjectConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastNetworkObjectConfig")
	}
	var output types.NetworkObjectConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastNetworkObjectConfig")
	}
	return output
}

func CastNetworkObjectStatus(in interface{}) types.NetworkObjectStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastNetworkObjectStatus")
	}
	var output types.NetworkObjectStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastNetworkObjectStatus")
	}
	return output
}

func CastNetworkServiceConfig(in interface{}) types.NetworkServiceConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastNetworkServiceConfig")
	}
	var output types.NetworkServiceConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastNetworkServiceConfig")
	}
	return output
}

func CastNetworkServiceStatus(in interface{}) types.NetworkServiceStatus {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastNetworkServiceStatus")
	}
	var output types.NetworkServiceStatus
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastNetworkServiceStatus")
	}
	return output
}

func CastNetworkServiceMetrics(in interface{}) types.NetworkServiceMetrics {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastNetworkServiceMetrics")
	}
	var output types.NetworkServiceMetrics
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastNetworkServiceSMetrics")
	}
	return output
}

func CastDeviceNetworkConfig(in interface{}) types.DeviceNetworkConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastDeviceNetworkConfig")
	}
	var output types.DeviceNetworkConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastDeviceNetworkConfig")
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

func CastZbootStatus(in interface{}) types.ZbootStatus {
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
