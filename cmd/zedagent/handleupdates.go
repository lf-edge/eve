// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Pull AppInstanceConfig from ZedCloud, make it available for zedmanager
// publish AppInstanceStatus to ZedCloud.

package main

import (
	"fmt"
	"github.com/zededa/go-provision/types"
)

func initMaps() {

	initBaseOsMaps()
	initCertObjMaps()
	initDownloaderMaps()
	initVerifierMaps()
}
func createBaseOsDownloaderConfig(safename string,
	sc *types.StorageConfig) {
	createDownloaderConfig(baseOsObj, safename, sc)
}

func createCertObjDownloaderConfig(safename string,
	sc *types.StorageConfig) {
	createDownloaderConfig(baseOsObj, safename, sc)
}

// XXX this function is not used
func createBaseOsVerifierConfig(safename string,
	sc *types.StorageConfig, checkCerts bool) {
	createVerifierConfig(baseOsObj, safename, sc, checkCerts)
}

func removeBaseOsDownloaderConfig(safename string) {
	removeDownloaderConfig(baseOsObj, safename)
}

func lookupBaseOsDownloaderStatus(safename string) (*types.DownloaderStatus, error) {
	return lookupDownloaderStatus(baseOsObj, safename)
}

func lookupCertObjDownloaderStatus(safename string) (*types.DownloaderStatus, error) {
	return lookupDownloaderStatus(certObj, safename)
}

func removeCertObjDownloaderConfig(safename string) {
	removeDownloaderConfig(certObj, safename)
}

func removeBaseOsVerifierConfig(safename string) {
	removeVerifierConfig(baseOsObj, safename)
}
func lookupBaseOsVerificationStatus(safename string) (*types.VerifyImageStatus, error) {
	return lookupVerificationStatus(baseOsObj, safename)
}

func lookupBaseOsVerificationStatusSha256(sha256 string) (*types.VerifyImageStatus, error) {

	return lookupVerificationStatusSha256(baseOsObj, sha256)
}

func lookupBaseOsVerificationStatusAny(safename string, sha256 string) (*types.VerifyImageStatus, error) {
	return lookupVerificationStatusAny(baseOsObj, safename, sha256)

}

func appendError(allErrors string, prefix string, lasterr string) string {
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr)
}

func formLookupKey(objType string, uuidStr string) string {
	return objType + "x" + uuidStr
}
