// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"github.com/lf-edge/eden/pkg/controller"
	"github.com/lf-edge/eden/pkg/controller/einfo"
	"github.com/lf-edge/eden/pkg/controller/elog"
	"github.com/lf-edge/eve/api/go/config"
	"testing"
	"time"
)

//TestBaseImage test base image loading into eve
func TestBaseImage(t *testing.T) {
	ctx, err := controller.CloudPrepare()
	if err != nil {
		t.Fatalf("CloudPrepare: %s", err)
	}
	vars := ctx.GetVars()
	var baseImageTests = []struct {
		dataStoreID       string
		imageID           string
		baseID            string
		imageRelativePath string
		imageFormat       config.Format
		eveBaseRef        string
	}{
		{eServerDataStoreID,

			"1ab8761b-5f89-4e0b-b757-4b87a9fa93ec",

			"22b8761b-5f89-4e0b-b757-4b87a9fa93ec",

			"../../installer/rootfs.img", // the first .. required to enforce our own FS view
			config.Format_QCOW2,
			vars.EveBaseVersion,
		},
	}
	for _, tt := range baseImageTests {
		baseOSVersion := tt.eveBaseRef
		t.Run(baseOSVersion, func(t *testing.T) {

			err = prepareBaseImageLocal(ctx, tt.dataStoreID, tt.imageID, tt.baseID, tt.imageRelativePath, tt.imageFormat, baseOSVersion)

			if err != nil {
				t.Fatal("Fail in prepare base image from local file: ", err)
			}
			deviceCtx, err := ctx.GetDeviceFirst()
			if err != nil {
				t.Fatal("Fail in get first device: ", err)
			}
			deviceCtx.SetBaseOSConfig([]string{tt.baseID})
			devUUID := deviceCtx.GetID()
			err = ctx.ConfigSync(deviceCtx)
			if err != nil {
				t.Fatal("Fail in sync config with controller: ", err)
			}
			t.Run("Started", func(t *testing.T) {
				err := ctx.InfoChecker(devUUID, map[string]string{"devId": devUUID.String(), "shortVersion": baseOSVersion}, einfo.ZInfoDevSW, einfo.HandleFirst, einfo.InfoAny, 300)
				if err != nil {
					t.Fatal("Fail in waiting for base image update init: ", err)
				}
			})
			t.Run("Downloaded", func(t *testing.T) {
				err := ctx.InfoChecker(devUUID, map[string]string{"devId": devUUID.String(), "shortVersion": baseOSVersion, "downloadProgress": "100"}, einfo.ZInfoDevSW, einfo.HandleFirst, einfo.InfoAny, 1500)
				if err != nil {
					t.Fatal("Fail in waiting for base image download progress: ", err)
				}
			})
			t.Run("Logs", func(t *testing.T) {
				if !checkLogs {
					t.Skip("no LOGS flag set - skipped")
				}
				err = ctx.LogChecker(devUUID, map[string]string{"devId": devUUID.String(), "eveVersion": baseOSVersion}, elog.HandleFirst, elog.LogAny, 1200)
				if err != nil {
					t.Fatal("Fail in waiting for base image logs: ", err)
				}
			})
			timeout := time.Duration(1200)

			if !checkLogs {
				timeout = 2400
			}
			t.Run("Active", func(t *testing.T) {
				err = ctx.InfoChecker(devUUID, map[string]string{"devId": devUUID.String(), "shortVersion": baseOSVersion, "status": "INSTALLED", "partitionState": "(inprogress|active)"}, einfo.ZInfoDevSW, einfo.HandleFirst, einfo.InfoAny, timeout)
				if err != nil {
					t.Fatal("Fail in waiting for base image installed status: ", err)
				}
			})
		})
	}

}
