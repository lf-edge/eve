// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
)

// seams collects the small one-off dependencies that unit tests
// substitute. They live behind function-pointer fields on a single
// struct so the context only carries one field per seam category
// (paths, zboot, seams) rather than a separate field per call. Defaulted
// in Run() to thin wrappers around the production packages.
type seams struct {
	isHVTypeKube        func() bool
	isVersionHVTypeKube func(version string) (bool, error)
	getNodeDrainStatus  func(sub pubsub.Subscription) *kubeapi.NodeDrainStatus
	requestNodeDrain    func(pub pubsub.Publication, requester kubeapi.DrainRequester, ctxStr string) error
}

// defaultSeams returns the production-default seams. Run() captures
// logArg so the kubeapi adapter can pass it through.
func defaultSeams(logArg *base.LogObject) seams {
	return seams{
		isHVTypeKube:        base.IsHVTypeKube,
		isVersionHVTypeKube: base.IsVersionHVTypeKube,
		getNodeDrainStatus: func(sub pubsub.Subscription) *kubeapi.NodeDrainStatus {
			return kubeapi.GetNodeDrainStatus(sub, logArg)
		},
		requestNodeDrain: kubeapi.RequestNodeDrain,
	}
}

// Zboot wraps the subset of pkg/pillar/zboot that baseosmgr uses. The
// realZboot adapter delegates to the package; unit tests substitute an
// in-memory implementation so they can drive partition state without
// touching grubenv or invoking zboot scripts.
type Zboot interface {
	// Inventory + lookup
	GetCurrentPartition() string
	GetOtherPartition() string
	GetValidPartitionLabels() []string
	IsValidPartitionLabel(string) bool
	IsCurrentPartition(string) bool
	IsOtherPartition(string) bool

	// Per-partition state read
	GetPartitionState(string) string
	GetPartitionDevname(string) string
	GetPartitionSizeInBytes(string) uint64
	GetShortVersion(string) (string, error)
	GetLongVersion(string) string

	// State write
	SetOtherPartitionStateUpdating()
	SetOtherPartitionStateUnused()
	MarkCurrentPartitionStateActive() error

	// Image install
	WriteToPartition(image, partName string) error
}

type realZboot struct {
	log *base.LogObject
}

func (r *realZboot) GetCurrentPartition() string         { return zboot.GetCurrentPartition() }
func (r *realZboot) GetOtherPartition() string           { return zboot.GetOtherPartition() }
func (r *realZboot) GetValidPartitionLabels() []string   { return zboot.GetValidPartitionLabels() }
func (r *realZboot) IsValidPartitionLabel(s string) bool { return zboot.IsValidPartitionLabel(s) }
func (r *realZboot) IsCurrentPartition(s string) bool    { return zboot.IsCurrentPartition(s) }
func (r *realZboot) IsOtherPartition(s string) bool      { return zboot.IsOtherPartition(s) }
func (r *realZboot) GetPartitionState(s string) string   { return zboot.GetPartitionState(s) }
func (r *realZboot) GetPartitionDevname(s string) string { return zboot.GetPartitionDevname(s) }
func (r *realZboot) GetPartitionSizeInBytes(s string) uint64 {
	return zboot.GetPartitionSizeInBytes(s)
}
func (r *realZboot) GetShortVersion(s string) (string, error) {
	return zboot.GetShortVersion(r.log, s)
}
func (r *realZboot) GetLongVersion(s string) string { return zboot.GetLongVersion(s) }
func (r *realZboot) SetOtherPartitionStateUpdating() {
	zboot.SetOtherPartitionStateUpdating(r.log)
}
func (r *realZboot) SetOtherPartitionStateUnused() {
	zboot.SetOtherPartitionStateUnused(r.log)
}
func (r *realZboot) MarkCurrentPartitionStateActive() error {
	return zboot.MarkCurrentPartitionStateActive(r.log)
}
func (r *realZboot) WriteToPartition(image, partName string) error {
	return zboot.WriteToPartition(r.log, image, partName)
}
