// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"github.com/lf-edge/eden/pkg/controller"
	"github.com/lf-edge/eden/pkg/controller/einfo"
	"github.com/lf-edge/eden/pkg/controller/elog"
	"testing"
	"time"
)

//TestAdamOnBoard test onboarding into controller
func TestAdamOnBoard(t *testing.T) {
	ctx, err := controller.CloudPrepare()
	if err != nil {
		t.Fatalf("CloudPrepare: %s", err)
	}
	vars := ctx.GetVars()
	devUUID, err := ctx.GetDeviceFirst()
	if devUUID == nil {
		t.Logf("Try to add onboarding")
		err = ctx.Register(vars.EveCert, vars.EveSerial)
		if err != nil {
			t.Fatal(err)
		}
		res, err := ctx.OnBoardList()
		if err != nil {
			t.Fatal(err)
		}
		if len(res) == 0 {
			t.Fatal("No onboard in list")
		}
		t.Log(res)

		maxRepeat := 20
		delayTime := 20 * time.Second

		for i := 0; i < maxRepeat; i++ {
			cmdOut, err := ctx.DeviceList()
			if err != nil {
				t.Fatal(err)
			}
			if len(cmdOut) > 0 {
				t.Logf("Done onboarding in adam!")
				t.Logf("Device uuid: %s", cmdOut)
				return
			}
			t.Logf("Attempt to list devices (%d) of (%d)", i, maxRepeat)
			time.Sleep(delayTime)
		}
		t.Fatal("Onboarding timeout")
	}
}

//TestControllerSetConfig test config set via controller
func TestControllerSetConfig(t *testing.T) {
	ctx, err := controller.CloudPrepare()
	if err != nil {
		t.Fatalf("CloudPrepare: %s", err)
	}
	deviceCtx, err := ctx.GetDeviceFirst()
	if err != nil {
		t.Fatal("Fail in get first device: ", err)
	}
	err = ctx.ConfigSync(deviceCtx)
	if err != nil {
		t.Fatal("Fail in config sync with device: ", err)
	}
}

//TestControllerGetConfig test config get via controller
func TestControllerGetConfig(t *testing.T) {
	ctx, err := controller.CloudPrepare()
	if err != nil {
		t.Fatalf("CloudPrepare: %s", err)
	}
	devUUID, err := ctx.GetDeviceFirst()
	if err != nil {
		t.Fatal("Fail in get first device: ", err)
	}
	config, err := ctx.ConfigGet(devUUID.GetID())
	if err != nil {
		t.Fatal("Fail in set config: ", err)
	}
	t.Log(config)
}

//TestAdamOnBoard test logs flow
func TestControllerLogs(t *testing.T) {
	ctx, err := controller.CloudPrepare()
	if err != nil {
		t.Fatalf("CloudPrepare: %s", err)
	}
	devUUID, err := ctx.GetDeviceFirst()
	if err != nil {
		t.Fatal("Fail in get first device: ", err)
	}
	t.Log(devUUID.GetID())
	err = ctx.LogChecker(devUUID.GetID(), map[string]string{"devId": devUUID.GetID().String()}, elog.HandleFirst, elog.LogAny, 600)
	if err != nil {
		t.Fatal("Fail in waiting for logs: ", err)
	}
}

//TestControllerInfo test info flow
func TestControllerInfo(t *testing.T) {
	ctx, err := controller.CloudPrepare()
	if err != nil {
		t.Fatalf("CloudPrepare: %s", err)
	}
	devUUID, err := ctx.GetDeviceFirst()
	if err != nil {
		t.Fatal("Fail in get first device: ", err)
	}
	t.Log(devUUID.GetID())
	err = ctx.InfoChecker(devUUID.GetID(), map[string]string{"devId": devUUID.GetID().String()}, einfo.ZInfoDevSW, einfo.HandleFirst, einfo.InfoAny, 300)
	if err != nil {
		t.Fatal("Fail in waiting for info: ", err)
	}
}
