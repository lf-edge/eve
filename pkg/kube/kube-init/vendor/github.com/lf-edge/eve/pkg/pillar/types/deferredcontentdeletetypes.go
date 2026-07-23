// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
)

// DeferredContentDeleteStatus records a content-tree delete that volumemgr has
// deferred (timer.defer.content.delete) so the content's CAS blobs and image are
// kept for possible reuse instead of being deleted and immediately
// re-downloaded.
//
// It is published Persistent so the deferral survives a reboot — in particular
// the EVE-kvm->EVE-k boot-disk conversion, which deletes the running app before
// repartitioning and reboots. On the next boot volumemgr re-reads these records;
// the boot-time GC keeps the listed blobs and image until DeleteTime, and the
// actual delete happens at expiry (or is cancelled when the content tree is
// re-created and reuses the still-present blobs).
type DeferredContentDeleteStatus struct {
	ContentID         uuid.UUID // also the publication key (matches ContentTreeStatus.Key())
	GenerationCounter int64
	ReferenceID       string    // CAS image reference to remove at expiry
	Blobs             []string  // blob sha256 (lowercase, no "sha256:" prefix) to keep then reap
	DeleteTime        time.Time // when the deferred delete becomes due
}

// Key is the ContentID, matching ContentTreeStatus.Key() so a re-created
// content tree maps 1:1 to its pending deferred delete.
func (status DeferredContentDeleteStatus) Key() string {
	return status.ContentID.String()
}

// LogCreate :
func (status DeferredContentDeleteStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.DeferredContentDeleteStatusLogType, "",
		status.ContentID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("reference-id", status.ReferenceID).
		AddField("blob-count-int64", len(status.Blobs)).
		AddField("delete-time", status.DeleteTime.String()).
		Noticef("Deferred content delete create")
}

// LogModify :
func (status DeferredContentDeleteStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.DeferredContentDeleteStatusLogType, "",
		status.ContentID, status.LogKey())
	logObject.CloneAndAddField("reference-id", status.ReferenceID).
		AddField("blob-count-int64", len(status.Blobs)).
		AddField("delete-time", status.DeleteTime.String()).
		Noticef("Deferred content delete modify")
}

// LogDelete :
func (status DeferredContentDeleteStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.DeferredContentDeleteStatusLogType, "",
		status.ContentID, status.LogKey())
	logObject.Noticef("Deferred content delete delete")
	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status DeferredContentDeleteStatus) LogKey() string {
	return string(base.DeferredContentDeleteStatusLogType) + "-" + status.Key()
}
