// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumehandlers

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"time"
)

// commonVolumeHandler stores common data and implements common functions
// that may be re-implemented in explicit handlers
type commonVolumeHandler struct {
	volumeManager VolumeMgr
	status        *types.VolumeStatus
	log           *base.LogObject
}

func (handler *commonVolumeHandler) CreateSnapshot() (interface{}, time.Time, error) {
	return nil, time.Time{}, nil
}

func (handler *commonVolumeHandler) RollbackToSnapshot(snapshotMeta interface{}) error { return nil }

func (handler *commonVolumeHandler) DeleteSnapshot(snapshotMeta interface{}) error { return nil }

func (handler *commonVolumeHandler) PrepareVolume() error { return nil }

func (handler *commonVolumeHandler) HandlePrepared() (bool, error) { return true, nil }

func (handler *commonVolumeHandler) UsageFromStatus() uint64 {
	sizeToUseInCalculation := uint64(handler.status.CurrentSize)
	hasNoAppReferences := false
	cfg := handler.volumeManager.LookupVolumeConfig(handler.status.Key())
	if cfg == nil {
		// we have no config with this volume, so it cannot have app references
		handler.log.Noticef("UsageFromStatus: Volume %s not found in VolumeConfigs, assume no app references",
			handler.status.Key())
		hasNoAppReferences = true
	} else {
		hasNoAppReferences = cfg.HasNoAppReferences
	}
	if handler.status.ReadOnly {
		// it is ReadOnly and will not grow
		handler.log.Noticef("UsageFromStatus: Volume %s is ReadOnly, use CurrentSize",
			handler.status.Key())
	} else if hasNoAppReferences {
		// it has no apps pointing onto it in new config
		handler.log.Noticef("UsageFromStatus: Volume %s has no app references, use CurrentSize",
			handler.status.Key())
	} else {
		// use MaxVolSize in other cases
		handler.log.Noticef("UsageFromStatus: Use MaxVolSize for Volume %s",
			handler.status.Key())
		sizeToUseInCalculation = handler.status.MaxVolSize
	}
	return sizeToUseInCalculation
}
