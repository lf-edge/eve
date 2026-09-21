// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
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

// contentTreeTracker follows the info messages of many content trees and
// keeps the latest one per tree, so that a test deploying many content trees
// at once can look at their overall state without draining the watch channels
// itself.
type contentTreeTracker struct {
	mu     sync.Mutex
	latest map[uuid.UUID]*eveinfo.ZInfoContentTree
	stops  []func()
}

// trackContentTrees starts following the info of the given content trees.
// Call stop when done.
func trackContentTrees(device *evetest.EdgeDevice, ctUUIDs []uuid.UUID) *contentTreeTracker {
	tracker := &contentTreeTracker{
		latest: make(map[uuid.UUID]*eveinfo.ZInfoContentTree, len(ctUUIDs)),
	}
	for _, ctUUID := range ctUUIDs {
		updates, stop := device.WatchContentTreeInfo(ctUUID)
		tracker.stops = append(tracker.stops, stop)
		go func(ctUUID uuid.UUID) {
			for info := range updates {
				tracker.mu.Lock()
				tracker.latest[ctUUID] = info
				tracker.mu.Unlock()
			}
		}(ctUUID)
	}
	return tracker
}

// get returns the latest reported info of the content tree, or nil if the
// device has not reported it yet.
func (tracker *contentTreeTracker) get(ctUUID uuid.UUID) *eveinfo.ZInfoContentTree {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.latest[ctUUID]
}

// stop ends all the watches started by trackContentTrees.
func (tracker *contentTreeTracker) stop() {
	for _, stop := range tracker.stops {
		stop()
	}
}

// contentTreeHasError reports whether the latest report of the content tree
// carries an error, i.e. whether its download has failed and parked.
func contentTreeHasError(info *eveinfo.ZInfoContentTree) bool {
	return info.GetErr().GetDescription() != ""
}

// contentTreeIsLoaded reports whether all blobs of the content tree have been
// downloaded, verified and loaded into the content-addressable store. EVE
// reports its internal LOADED state as DELIVERED in the API (see
// SwState.ZSwState in pillar), so both are accepted.
func contentTreeIsLoaded(info *eveinfo.ZInfoContentTree) bool {
	if info == nil {
		return false
	}
	return info.GetState() == eveinfo.ZSwState_DELIVERED ||
		info.GetState() == eveinfo.ZSwState_LOADED
}

// describeContentTree renders the state a content tree is in, e.g.
// "DOWNLOAD_STARTED at 0%", with the error description appended when the
// content tree reports one.
func describeContentTree(info *eveinfo.ZInfoContentTree) string {
	if info == nil {
		return "not reported yet"
	}
	desc := fmt.Sprintf("%s at %d%%", info.GetState(), info.GetProgressPercentage())
	if errDesc := info.GetErr().GetDescription(); errDesc != "" {
		desc += ", error: " + errDesc
	}
	return desc
}

// logDeviceObjectStates logs how many content trees, blobs and downloads the
// device itself currently holds in each state. It tells a device that is still
// working, or has finished, apart from one whose reports have not reached the
// controller yet: every state change is one info message, sent one after
// another, and with hundreds of objects the last report can trail the device
// by minutes.
func logDeviceObjectStates(device *evetest.EdgeDevice) {
	log := evetest.Logger()
	const script = `for d in /run/volumemgr/ContentTreeStatus /run/volumemgr/BlobStatus \
	/run/downloader/DownloaderStatus; do
	echo "== $d"
	cat "$d"/*.json 2>/dev/null | grep -oE '"State": *[0-9]+' | grep -oE '[0-9]+$' | sort | uniq -c
done`
	out, _, err := device.RunShellScript(script, time.Minute, 0)
	if err != nil {
		log.Warnf("Cannot summarize the device's object states: %v", err)
		return
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		switch {
		case len(fields) == 2 && fields[0] == "==":
			log.Infof("device view of %s:", fields[1])
		case len(fields) == 2:
			state, err := strconv.Atoi(fields[1])
			if err != nil {
				continue
			}
			log.Infof("  %s objects in state %s", fields[0], pillartypes.SwState(state))
		}
	}
}

// logDownloaderView logs what the downloader microservice itself records for
// up to maxBlobs of the blobs listed in namesBySHA (state, downloaded bytes,
// retries, error). It is meant for diagnosing a download that never finished:
// a blob stuck at zero bytes with zero retries and no error is a download the
// downloader has stopped working on without noticing, whereas a slow or
// failing download shows progress, retries or an error.
func logDownloaderView(device *evetest.EdgeDevice, namesBySHA map[string]string,
	maxBlobs int) {
	log := evetest.Logger()
	logged := 0
	for sha256Hex, name := range namesBySHA {
		if logged == maxBlobs {
			break
		}
		logged++
		data, err := device.ReadFile("/run/downloader/DownloaderStatus/" +
			strings.ToLower(sha256Hex) + ".json")
		if err != nil {
			log.Warnf("Cannot read the DownloaderStatus of %s: %v", name, err)
			continue
		}
		var status pillartypes.DownloaderStatus
		if err := json.Unmarshal(data, &status); err != nil {
			log.Warnf("Cannot parse the DownloaderStatus of %s: %v", name, err)
			continue
		}
		log.Infof("downloader view of %s: state=%s progress=%d%% bytes=%d/%d "+
			"retries=%d error=%q", name, status.State, status.Progress,
			status.CurrentSize, status.TotalSize, status.RetryCount, status.Error)
	}
}
