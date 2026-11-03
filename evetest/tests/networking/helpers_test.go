// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"

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

// expectNIInfo waits until the network instance info satisfies matcher, and
// returns the info that did. It first checks last, the newest info an earlier
// wait already took from updates (nil if none): EVE publishes network instance
// info only when the network instance's status changes, so the state waited for
// can be in that message already, with no further message to come.
func expectNIInfo(t *WithT, updates <-chan *eveinfo.ZInfoNetworkInstance,
	last *eveinfo.ZInfoNetworkInstance, timeout time.Duration,
	matcher types.GomegaMatcher) *eveinfo.ZInfoNetworkInstance {
	if last != nil {
		// Match also returns an error when a StopIf fires; Expect reports it.
		if matched, err := matcher.Match(last); matched || err != nil {
			t.Expect(last).To(matcher)
			return last
		}
	}
	var info *eveinfo.ZInfoNetworkInstance
	t.Eventually(updates, timeout).Should(Receive(&info, matcher))
	return info
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
