// Copyright (c) 2020-2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/go-qemu/qmp"
	"github.com/sirupsen/logrus"
	"os"
	"time"
)

// this package implements subset of
//     https://qemu.weilnetz.de/doc/qemu-qmp-ref.html

const (
	sockTimeout   = 10 * time.Second
	qmpRetries    = 5
	qmpRetrySleep = 3 * time.Second
)

// execRawCmd will retry (if doReply is set) for qmpRetries times sleeping
// qmpRetrySleep between attempts
func execRawCmd(socket, cmd string, doRetry bool) ([]byte, error) {
	var retry int
	logrus.Debugf("executing QMP command: %s", cmd)
	var err error
	var monitor *qmp.SocketMonitor

	if doRetry {
		retry = qmpRetries
	}
	for retry >= 0 {
		if monitor, err = qmp.NewSocketMonitor("unix", socket, sockTimeout); err != nil {
			retry = retry - 1
			time.Sleep(qmpRetrySleep)
			continue
		}
		break
	}
	if err != nil {
		return nil, err
	}
	// We might have reached retry zero in the above loop, in which case
	// we will still try the Connect once.
	for retry >= 0 {
		if err = monitor.Connect(); err != nil {
			retry = retry - 1
			time.Sleep(qmpRetrySleep)
			continue
		}
		defer monitor.Disconnect()
		break
	}
	if err != nil {
		return nil, err
	}
	return monitor.Run([]byte(cmd))
}

func execContinue(socket string) error {
	_, err := execRawCmd(socket, `{ "execute": "cont" }`, true)
	return err
}

func execStop(socket string) error {
	_, err := execRawCmd(socket, `{ "execute": "stop" }`, true)
	return err
}

func execShutdown(socket string) error {
	_, err := execRawCmd(socket, `{ "execute": "system_powerdown" }`, true)
	return err
}

func execQuit(socket string) error {
	_, err := execRawCmd(socket, `{ "execute": "quit" }`, true)
	return err
}

func execVNCPassword(socket string, password string) error {
	vncSetPwd := fmt.Sprintf(`{ "execute": "change-vnc-password", "arguments": { "password": "%s" } }`, password)
	_, err := execRawCmd(socket, vncSetPwd, true)
	return err
}

// QmpExecDeviceDelete removes a device
func QmpExecDeviceDelete(socket, id string) error {
	qmpString := fmt.Sprintf(`{ "execute": "device_del", "arguments": { "id": "%s"}}`, id)
	_, err := execRawCmd(socket, qmpString, true)
	return err
}

// QmpExecDeviceAdd adds a usb device via busnum/devnum
func QmpExecDeviceAdd(socket, id string, busnum, devnum uint16) error {
	qmpString := fmt.Sprintf(`{ "execute": "device_add", "arguments": { "driver": "usb-host", "hostbus": %d, "hostaddr": %d, "id": "%s"} }`, busnum, devnum, id)
	_, err := execRawCmd(socket, qmpString, true)
	return err
}

// There is errors.Join(), but stupid Yetus has old golang
// and complains with "Join not declared by package errors".
// Use our own.
func joinErrors(err1, err2 error) error {
	if err1 == nil {
		return err2
	}
	if err2 == nil {
		return err1
	}

	return fmt.Errorf("%v; %v", err1, err2)
}

func getQemuStatus(socket string) (types.SwState, error) {
	// lets parse the status according to
	// https://github.com/qemu/qemu/blob/master/qapi/run-state.json#L8
	qmpStatusMap := map[string]types.SwState{
		"finish-migrate": types.PAUSED,
		"inmigrate":      types.PAUSING,
		"paused":         types.PAUSED,
		"postmigrate":    types.PAUSED,
		"prelaunch":      types.PAUSED,
		"restore-vm":     types.PAUSED,
		"running":        types.RUNNING,
		"save-vm":        types.PAUSED,
		"shutdown":       types.HALTING,
		"suspended":      types.PAUSED,
		"watchdog":       types.PAUSING,
		"colo":           types.PAUSED,
		"preconfig":      types.PAUSED,
	}

	// We do several retries, because correct QEMU status is very crucial to EVE
	// and if for some reason (https://github.com/digitalocean/go-qemu/pull/210)
	// the status is unexpected, EVE stops QEMU and game over.
	var errs error
	state := types.UNKNOWN
	for attempt := 1; attempt <= qmpRetries; attempt++ {
		raw, err := execRawCmd(socket, `{ "execute": "query-status" }`,
			false)
		if err != nil {
			err = fmt.Errorf("[attempt %d] qmp status failed for QMP socket '%s': err: '%v'; (JSON response: '%s')",
				attempt, socket, err, raw)
			errs = joinErrors(errs, err)
			time.Sleep(qmpRetrySleep)
			continue
		}

		var result struct {
			ID     string `json:"id"`
			Return struct {
				Running    bool   `json:"running"`
				Singlestep bool   `json:"singlestep"`
				Status     string `json:"status"`
			} `json:"return"`
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		err = dec.Decode(&result)
		if err != nil {
			err = fmt.Errorf("[attempt %d] failed to parse QMP status response for QMP socket '%s': err: '%v'; (JSON response: '%s')",
				attempt, socket, err, raw)
			errs = joinErrors(errs, err)
			time.Sleep(qmpRetrySleep)
			continue
		}
		var matched bool
		if state, matched = qmpStatusMap[result.Return.Status]; !matched {
			err = fmt.Errorf("[attempt %d] unknown QMP status '%s' for QMP socket '%s'; (JSON response: '%s')",
				attempt, result.Return.Status, socket, raw)
			errs = joinErrors(errs, err)
			time.Sleep(qmpRetrySleep)
			continue
		}

		if errs != nil {
			logrus.Errorf("getQemuStatus: %d retrieving status attempts failed '%v', but eventually '%s' status was retrieved, so return SUCCESS and continue",
				attempt, errs, result.Return.Status)
			errs = nil
		}

		// Success
		break
	}

	return state, errs
}

func qmpEventHandler(listenerSocket, executorSocket string) {
	monitor, err := qmp.NewSocketMonitor("unix", listenerSocket, sockTimeout)
	if err != nil {
		logrus.Errorf("qmpEventHandler: Exception while getting monitor of listenerSocket: %s. %s", listenerSocket, err.Error())
		return
	}
	if err := monitor.Connect(); err != nil {
		logrus.Errorf("qmpEventHandler: Exception while connecting listenerSocket: %s. %s", listenerSocket, err.Error())
		return
	}
	defer monitor.Disconnect()

	eventChan, err := monitor.Events(context.Background())
	if err != nil {
		logrus.Errorf("qmpEventHandler: Exception while getting event channel from listenerSocket: %s. %s", listenerSocket, err.Error())
		return
	}
	for {
		if _, err := os.Stat(listenerSocket); err != nil {
			logrus.Errorf("qmpEventHandler: Exception while accessing listenerSocket: %s. %s", listenerSocket, err.Error())
			return
		}
		select {
		case event := <-eventChan:
			switch event.Event {
			case "SHUTDOWN":
				logrus.Infof("qmpEventHandler: Received event: %s event details: %v. Calling quit on socket: %s", event.Event, event.Data, executorSocket)
				if err := execStop(executorSocket); err != nil {
					logrus.Errorf("qmpEventHandler: Exception while stopping domain with socket: %s. %s", executorSocket, err.Error())
				}
				if err := execQuit(executorSocket); err != nil {
					logrus.Errorf("qmpEventHandler: Exception while quitting domain with socket: %s. %s", executorSocket, err.Error())
				}
			default:
				//Not handling the following events: RESUME, NIC_RX_FILTER_CHANGED, RTC_CHANGE, POWERDOWN, STOP
				logrus.Warnf("qmpEventHandler: Unhandled event: %s from QMP socket: %s", event.Event, listenerSocket)
			}
		}
	}
}
