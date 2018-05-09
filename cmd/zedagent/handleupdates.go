// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Pull AppInstanceConfig from ZedCloud, make it available for zedmanager
// publish AppInstanceStatus to ZedCloud.

package zedagent

import (
	"fmt"
)

func initMaps() {

	initBaseOsMaps()
	initCertObjMaps()
	initDownloaderMaps()
	initVerifierMaps()
}

func appendError(allErrors string, prefix string, lasterr string) string {
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr)
}

func formLookupKey(objType string, uuidStr string) string {
	return objType + "x" + uuidStr
}
