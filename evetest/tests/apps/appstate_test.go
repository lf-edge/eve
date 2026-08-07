// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Pillar's own view of the app instance: pubsub publications and persisted state
// keyed by app UUID.
//
// Rule for this file: one reader per (agent, topic) question. Tests do not call
// evetest.ReadPublication or ReadAllPublications directly - they call a named
// reader here, so the knowledge of which agent publishes what, and how a
// transient read failure is reported, lives in one place.

package apps_test

import (
	"strconv"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// appPublication returns the publication of type T that belongs to appUUID.
//
// Every pillar status type keyed by app instance has a Key() returning the app
// UUID string (types.AppInstanceStatus.Key, types.DomainStatus.Key), which is
// what the constraint expresses. evetest.ReadAllPublications derives the pubsub
// topic name from T itself, so instantiating this is all a new reader needs.
// Note that types.VolumeStatus does NOT satisfy the intent here even though it
// has a Key(): its key is "<volume-uuid>#<generation>", not an app UUID - see
// soleVolumeStatus in appvolumes_test.go for why volumes cannot be attributed to
// an app this way at all.
func appPublication[T interface{ Key() string }](
	dev *evetest.EdgeDevice, agent string, appUUID uuid.UUID) (item T, found bool) {
	pubs, err := evetest.ReadAllPublications[T](dev, agent, false)
	if err != nil {
		// Transient: a publication can vanish between being listed and being
		// copied. Report not-found and let the caller's Eventually retry.
		evetest.Logger().Warnf("appPublication: reading %s publications: %v", agent, err)
		return item, false
	}
	for _, pub := range pubs {
		if pub.Key() == appUUID.String() {
			return pub, true
		}
	}
	return item, false
}

// appPurgePhase returns the app's state and purge phase as zedmanager itself
// publishes them. This is what distinguishes "the purge finished" from "the purge
// is wedged": a purge parked on a VolumeRefStatus removal volumemgr will never
// confirm stays in DownloadAndVerify indefinitely and never even requests the new
// volume. That code is in zedmanager, so the failure mode is not specific to a
// hypervisor.
func appPurgePhase(dev *evetest.EdgeDevice, appUUID uuid.UUID) (
	state types.SwState, purge types.Inprogress, found bool) {
	status, found := appPublication[types.AppInstanceStatus](dev, "zedmanager", appUUID)
	if !found {
		return state, purge, false
	}
	return status.State, status.PurgeInprogress, true
}

// appDomainStatus returns domainmgr's published DomainStatus for the app. There
// is at most one, because DomainStatus is keyed by app UUID - which is exactly
// why it cannot be used to count workload generations (see listAppVMIRS and
// listKVMDomainDirs in appworkload_test.go). It is authoritative for the
// domain's id, name and attached disks.
func appDomainStatus(
	dev *evetest.EdgeDevice, appUUID uuid.UUID) (types.DomainStatus, bool) {
	return appPublication[types.DomainStatus](dev, "domainmgr", appUUID)
}

// purgeCounter reads the persisted purge counter zedmanager keeps for appUUID
// (pkg/pillar/types.UuidToNum, NumType "purgeCmdCounter"). This counter is
// exactly what a reboot mid-purge can corrupt - advancing the purge phase
// before the old generation is actually gone - and it is not republished
// anywhere in the EVE API, so it is read from the persisted pubsub state.
//
// found is false while the file does not exist, which is the expected state
// before an app's first purge.
func purgeCounter(
	dev *evetest.EdgeDevice, appUUID uuid.UUID) (counter uint32, found bool) {
	var rec types.UuidToNum
	if err := evetest.ReadPublication(
		dev, "zedmanager", true, appUUID.String(), &rec); err != nil {
		// Absent before the app's first purge, which is expected; a transient
		// read failure lands here too and the caller's retry absorbs it.
		return 0, false
	}
	return uint32(rec.Number), true
}

// inprogressName gives types.Inprogress a readable form for failure messages.
// The type has no String method of its own.
func inprogressName(p types.Inprogress) string {
	switch p {
	case types.NotInprogress:
		return "NotInprogress"
	case types.DownloadAndVerify:
		return "DownloadAndVerify"
	case types.BringDown:
		return "BringDown"
	case types.RecreateVolumes:
		return "RecreateVolumes"
	case types.BringUp:
		return "BringUp"
	}
	return "Inprogress(" + strconv.Itoa(int(p)) + ")"
}
