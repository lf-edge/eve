// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"strings"
	"time"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
)

// readBpduGuard reads the BPDU guard sysfs flag for a named bridge port.
// Returns "0", "1", or "" if the path cannot be read.
func readBpduGuard(device *evetest.EdgeDevice, bridgeName, portName string,
	sshTimeout time.Duration) string {
	path := "/sys/class/net/" + bridgeName + "/brif/" + portName + "/bpdu_guard"
	output, _, err := device.RunShellScript("cat "+path, sshTimeout, 0)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(output)
}

// niHasError is a matchers.SatisfyPredicate StopIf callback: it stops an
// Eventually early if the network instance has reached the ERROR state,
// instead of waiting out the full timeout.
func niHasError(info *eveinfo.ZInfoNetworkInstance) (string, bool) {
	stop := info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ERROR
	if stop {
		return "Network instance is in error state", true
	}
	return "", false
}

// appHasError is a matchers.SatisfyPredicate StopIf callback: it stops an
// Eventually early if the application instance has reached the ERROR state,
// instead of waiting out the full timeout.
func appHasError(info *eveinfo.ZInfoApp) (string, bool) {
	stop := info.State == eveinfo.ZSwState_ERROR
	if stop {
		return "Application instance is in error state", true
	}
	return "", false
}
