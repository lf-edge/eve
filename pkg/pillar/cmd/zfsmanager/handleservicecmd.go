// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfsmanager

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/vault"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

const (
	cmdRunCheckInterval = 30 * time.Second // the interval between schedule checks for run commands
	runTimeEveryH       = 1 * time.Hour
	runTimeEvery3H      = 3 * time.Hour
	runTimeEvery6H      = 6 * time.Hour
	runTimeEvery12H     = 12 * time.Hour
	runTimeEveryDay     = 24 * time.Hour
	runTimeEvery2Days   = 2 * runTimeEveryDay
	runTimeEvery3Days   = 3 * runTimeEveryDay
	runTimeEveryWeek    = 7 * runTimeEveryDay
	runTimeEvery2Weeks  = 2 * runTimeEveryWeek
	runTimeEveryMonth   = 30 * runTimeEveryDay
	runTimeEvery3Months = 3 * runTimeEveryMonth
	runTimeEvery6Months = 6 * runTimeEveryMonth
	runTimeEveryYear    = 12 * runTimeEveryMonth
)

// getNewRunTime - returns the time of the next run
func getNewRunTime(runType types.StorageCmdRunType) int64 {
	currentTime := time.Now()
	switch runType {
	case types.StorageCmdRunTypeUnspecified:
		return 0
	case types.StorageCmdRunTypeNotRun:
		return 0
	case types.StorageCmdRunTypeNow:
		return 0
	case types.StorageCmdRunTypeEveryHour:
		return currentTime.Add(runTimeEveryH).Unix()
	case types.StorageCmdRunTypeEvery3Hours:
		return currentTime.Add(runTimeEvery3H).Unix()
	case types.StorageCmdRunTypeEvery6Hours:
		return currentTime.Add(runTimeEvery6H).Unix()
	case types.StorageCmdRunTypeEvery12Hours:
		return currentTime.Add(runTimeEvery12H).Unix()
	case types.StorageCmdRunTypeEveryDay:
		return currentTime.Add(runTimeEveryDay).Unix()
	case types.StorageCmdRunTypeEvery2Days:
		return currentTime.Add(runTimeEvery2Days).Unix()
	case types.StorageCmdRunTypeEvery3Days:
		return currentTime.Add(runTimeEvery3Days).Unix()
	case types.StorageCmdRunTypeEveryWeek:
		return currentTime.Add(runTimeEveryWeek).Unix()
	case types.StorageCmdRunTypeEvery2Weeks:
		return currentTime.Add(runTimeEvery2Weeks).Unix()
	case types.StorageCmdRunTypeEveryMonth:
		return currentTime.Add(runTimeEveryMonth).Unix()
	case types.StorageCmdRunTypeEvery3Months:
		return currentTime.Add(runTimeEvery3Months).Unix()
	case types.StorageCmdRunTypeEvery6Months:
		return currentTime.Add(runTimeEvery6Months).Unix()
	case types.StorageCmdRunTypeEveryYear:
		return currentTime.Add(runTimeEveryYear).Unix()
	}
	return 0
}

// doServiceCmdStatusUpdate - updates the status for a ServiceCmd.
// Return true if changed
func doServiceCmdStatusUpdate(ctx *zfsContext,
	serviceCmdStatus *types.StorageServiceCmdStatus) bool {
	var changed bool
	serviceCmdConfigObj,
		err := ctx.subStorageCmdConfig.Get(serviceCmdStatus.Key())
	if err != nil {
		log.Errorf("cannot get serviceCmd config for %v",
			serviceCmdStatus.Key())
		return changed
	}
	serviceCmdConfig := serviceCmdConfigObj.(types.StorageServiceCmdConfig)

	if serviceCmdStatus.CmdRunType != serviceCmdConfig.CmdRunType {
		serviceCmdStatus.CmdRunType = serviceCmdConfig.CmdRunType
		changed = true
	}

	currentTime := time.Now().Unix()
	if serviceCmdStatus.LastUpdateTime == 0 &&
		serviceCmdStatus.LastChangeCmdRunTypeTime == 0 {
		serviceCmdStatus.LastUpdateTime = currentTime
		serviceCmdStatus.LastChangeCmdRunTypeTime = currentTime
		changed = true
	}

	return changed
}

// updateServiceCmdAfterRun - updates information about the command after
// it is launched to a new one.
func updateServiceCmdAfterRun(serviceCmd *types.StorageServiceCmdStatus) {
	if serviceCmd.CmdRunType == types.StorageCmdRunTypeNotRun ||
		serviceCmd.CmdRunType == types.StorageCmdRunTypeUnspecified {
		return
	}

	currentTime := time.Now().Unix()
	if serviceCmd.CmdRunType == types.StorageCmdRunTypeNow {
		serviceCmd.CmdRunType = types.StorageCmdRunTypeNotRun
	}
	serviceCmd.LastChangeCmdRunTypeTime = currentTime
	serviceCmd.LastRunTimeList = append(serviceCmd.LastRunTimeList, currentTime)
	serviceCmd.LastUpdateTime = currentTime
	serviceCmd.NextRunTime = getNewRunTime(serviceCmd.CmdRunType)
}

// runServiceCmd - initiates a command in zfs
func runServiceCmd(serviceCmd *types.StorageServiceCmdStatus) error {
	if output, err := zfs.RunServiceCmd(log,
		serviceCmd.PoolName, serviceCmd.CmdType); err != nil {
		return fmt.Errorf(
			"run service cmd %s for pool: %s failed. error: %s|%v",
			serviceCmd.Key(), serviceCmd.PoolName, output, err)
	}
	return nil
}

// maybeRunServiceCmd - checks commands for the scheduled run.
func maybeRunServiceCmd(ctx *zfsContext) {
	for _, el := range ctx.pubStorageCmdStatus.GetAll() {
		storageCmdStatus := el.(types.StorageServiceCmdStatus)
		currentTime := time.Now().Unix()

		if (storageCmdStatus.NextRunTime != 0 &&
			currentTime > storageCmdStatus.NextRunTime) ||
			storageCmdStatus.CmdRunType == types.StorageCmdRunTypeNow {
			if err := runServiceCmd(&storageCmdStatus); err != nil {
				log.Errorf("checkTimeForStorageServiceCmd: %s", err)
			} else {
				updateServiceCmdAfterRun(&storageCmdStatus)
			}
		}
		storageCmdStatus.LastUpdateTime = currentTime
		publishStorageCmdStatus(ctx, storageCmdStatus)
	}
}

func findServiceCmdStatusByKey(ctx *zfsContext, serviceCmdKey string) (
	*types.StorageServiceCmdStatus, error) {
	serviceCmdList := ctx.pubStorageCmdStatus.GetAll()
	for _, vc := range serviceCmdList {
		serviceCmdStatus := vc.(types.StorageServiceCmdStatus)
		if serviceCmdKey == serviceCmdStatus.Key() {
			return &serviceCmdStatus, nil
		}
	}
	return nil,
		fmt.Errorf("service cmd status with Key:%s not found", serviceCmdKey)
}

func handleStorageServiceCmdCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	handleStorageServiceCmdImpl(ctxArg, key, configArg, nil)
}

func handleStorageServiceCmdModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handleStorageServiceCmdImpl(ctxArg, key, configArg, oldConfigArg)
}

func handleStorageServiceCmdImpl(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	CmdConfig := configArg.(types.StorageServiceCmdConfig)
	log.Functionf("handleStorageServiceCmdImpl(%s)", key)
	ctx := ctxArg.(*zfsContext)
	cfgCmdKey := CmdConfig.Key()

	serviceCmdStatus, err := findServiceCmdStatusByKey(ctx, cfgCmdKey)
	if err != nil {
		serviceCmdStatus = &types.StorageServiceCmdStatus{
			PoolName:                 CmdConfig.PoolName,
			CmdType:                  CmdConfig.CmdType,
			CmdRunType:               CmdConfig.CmdRunType,
			LastUpdateTime:           0, // 0 - only when the new serviceCmdStatus
			NextRunTime:              getNewRunTime(CmdConfig.CmdRunType),
			LastChangeCmdRunTypeTime: 0, // 0 - only when the new serviceCmdStatus
		}
	}
	if doServiceCmdStatusUpdate(ctx, serviceCmdStatus) {
		// If, when receiving a new or updating an existing command,
		// regardless of the frequency of its launch, we need to force
		// this command to run when it arrives/updates,
		// then we should to uncomment the code:
		// if err := runServiceCmd(serviceCmdStatus); err != nil {
		//     log.Errorf("handleStorageServiceCmdImpl: %s", err)
		// } else {
		//     updateServiceCmdAfterRun(serviceCmdStatus)
		// }
		publishStorageCmdStatus(ctx, *serviceCmdStatus)
	}
}

func handleStorageServiceCmdDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	currentTime := time.Now().Unix()
	CmdConfig := configArg.(types.StorageServiceCmdConfig)
	log.Functionf("handleStorageServiceCmdImpl(%s)", key)
	ctx := ctxArg.(*zfsContext)
	cfgCmdKey := CmdConfig.Key()

	serviceCmdStatus, err := findServiceCmdStatusByKey(ctx, cfgCmdKey)
	if err != nil {
		log.Errorf("cannot found serviceCmd status for %s, err: %v",
			cfgCmdKey, err)
		return
	}

	// we not should delete status,
	// just change cmdRunType on StorageCmdRunTypeNotRun
	serviceCmdStatus.CmdRunType = types.StorageCmdRunTypeNotRun
	serviceCmdStatus.LastChangeCmdRunTypeTime = currentTime
	serviceCmdStatus.LastUpdateTime = currentTime
	serviceCmdStatus.NextRunTime = getNewRunTime(types.StorageCmdRunTypeNotRun)
	publishStorageCmdStatus(ctx, *serviceCmdStatus)
}

func storageServiceCmdTask(ctxPtr *zfsContext) {
	if vault.ReadPersistType() != types.PersistZFS {
		return
	}
	maybeRunServiceCmd(ctxPtr)

	t := time.NewTicker(cmdRunCheckInterval)
	for {
		select {
		case <-t.C:
			maybeRunServiceCmd(ctxPtr)
		}
	}
}

func publishStorageCmdStatus(ctx *zfsContext,
	status types.StorageServiceCmdStatus) {
	key := status.Key()
	log.Tracef("publishStorageCmdStatus(%s)\n", key)
	pub := ctx.pubStorageCmdStatus
	pub.Publish(key, status)
	log.Tracef("publishStorageCmdStatus(%s) done\n", key)
}
