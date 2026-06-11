// Copyright (c) 2020-2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/go-qemu/qmp"
	"github.com/sirupsen/logrus"
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
	cmd := `{ "execute": "cont" }`
	logrus.Debugf("executing QMP command: %s", cmd)
	_, err := execRawCmd(socket, cmd, true)
	return err
}

func execStop(socket string) error {
	cmd := `{ "execute": "stop" }`
	logrus.Debugf("executing QMP command: %s", cmd)
	_, err := execRawCmd(socket, cmd, true)
	return err
}

func execShutdown(socket string) error {
	cmd := `{ "execute": "system_powerdown" }`
	logrus.Debugf("executing QMP command: %s", cmd)
	_, err := execRawCmd(socket, cmd, true)
	return err
}

func execQuit(socket string) error {
	cmd := `{ "execute": "quit" }`
	logrus.Debugf("executing QMP command: %s", cmd)
	_, err := execRawCmd(socket, cmd, true)
	return err
}

// readQemuRunState issues a one-shot QMP query-status and returns the
// raw run-state string ("running", "internal-error", "paused", …).
// Used by qmpEventHandler on STOP because the STOP event itself
// carries no reason field.  Returns "" on any error.
func readQemuRunState(socket string) string {
	raw, err := execRawCmd(socket, `{ "execute": "query-status" }`, false)
	if err != nil {
		logrus.Debugf("readQemuRunState: %v", err)
		return ""
	}
	var resp struct {
		Return struct {
			Status string `json:"status"`
		} `json:"return"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		logrus.Debugf("readQemuRunState: parse: %v", err)
		return ""
	}
	return resp.Return.Status
}

// readPauseOnCrashFlag reads the current value of the
// debug.qemu.pause.on.crash global config item directly from pillar's
// on-disk pubsub publication.  qmpEventHandler runs in a goroutine
// without a Subscription, so we side-step the pubsub channel and just
// read the JSON.  Returns false on any error (missing file, parse
// failure, key not set).
func readPauseOnCrashFlag() bool {
	const path = "/run/global/ConfigItemValueMap/global.json"
	raw, err := os.ReadFile(path)
	if err != nil {
		logrus.Debugf("readPauseOnCrashFlag: %v", err)
		return false
	}
	var cfg types.ConfigItemValueMap
	if err := json.Unmarshal(raw, &cfg); err != nil {
		logrus.Warnf("readPauseOnCrashFlag: parse %s: %v", path, err)
		return false
	}
	return cfg.GlobalValueBool(types.QemuPauseOnCrash)
}

// execDumpGuestMemory triggers qemu's `dump-guest-memory` QMP command,
// writing the guest's physical RAM in ELF core format to outPath.
// The `paging=false` flag means "don't perform the guest pagewalk to
// produce a 'virtual' dump — just the raw GPA layout"; this is what
// WinDbg / crash can ingest after we tell them where the Windows
// kernel image landed (from the dump's note section).
func execDumpGuestMemory(socket, outPath string) error {
	cmd := fmt.Sprintf(`{ "execute": "dump-guest-memory", "arguments": { "paging": false, "protocol": "file:%s" } }`, outPath)
	logrus.Infof("executing QMP command: %s", cmd)
	_, err := execRawCmd(socket, cmd, true)
	return err
}

func execVNCPassword(socket string, password string) error {
	vncSetPwd := fmt.Sprintf(`{ "execute": "change-vnc-password", "arguments": { "password": "%s" } }`, password)
	// But log this:
	cmd := `{ "execute": "change-vnc-password", "arguments": { "password": <redacted> } }`
	logrus.Debugf("executing QMP command: %s", cmd)
	_, err := execRawCmd(socket, vncSetPwd, true)
	return err
}

// QmpExecDeviceDelete removes a device
func QmpExecDeviceDelete(socket, id string) error {
	qmpString := fmt.Sprintf(`{ "execute": "device_del", "arguments": { "id": "%s"}}`, id)
	logrus.Debugf("executing QMP command: %s", qmpString)
	_, err := execRawCmd(socket, qmpString, true)
	return err
}

// QmpExecDeviceAdd adds a usb device via busnum/devnum
func QmpExecDeviceAdd(socket, id string, busnum, devnum uint16) error {
	qmpString := fmt.Sprintf(`{ "execute": "device_add", "arguments": { "driver": "usb-host", "hostbus": %d, "hostaddr": %d, "id": "%s"} }`, busnum, devnum, id)
	logrus.Debugf("executing QMP command: %s", qmpString)
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
		cmd := `{ "execute": "query-status" }`
		logrus.Debugf("executing QMP command: %s", cmd)
		raw, err := execRawCmd(socket, cmd, false)
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

func qmpEventHandler(listenerSocket, executorSocket, domainName string) {
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

	// Using 'for range' ensures we exit when channel is closed (QMP connection lost).
	// This prevents infinite loop on VM restart when socket path is reused.
	for event := range eventChan {
		if _, err := os.Stat(listenerSocket); err != nil {
			logrus.Errorf("qmpEventHandler: Exception while accessing listenerSocket: %s. %s", listenerSocket, err.Error())
			return
		}
		switch event.Event {
		case "SHUTDOWN":
			logrus.Infof("qmpEventHandler: Received event: %s event details: %v. Calling quit on socket: %s", event.Event, event.Data, executorSocket)
			if err := execStop(executorSocket); err != nil {
				logrus.Errorf("qmpEventHandler: Exception while stopping domain with socket: %s. %s", executorSocket, err.Error())
			}
			if err := execQuit(executorSocket); err != nil {
				logrus.Errorf("qmpEventHandler: Exception while quitting domain with socket: %s. %s", executorSocket, err.Error())
			}
		case "STOP":
			// QMP's STOP event itself carries no reason field; the
			// reason for the stop is exposed via query-status as the
			// VM's run state.  After KVM_RUN -> -EFAULT, qemu's
			// accel/kvm/kvm-all.c calls vm_stop(RUN_STATE_INTERNAL_ERROR)
			// which fires this STOP and then `query-status` returns
			// {"status": "internal-error"}.  Capture the guest's
			// physical RAM as an ELF core file in that case, before
			// pillar's outer loop notices BROKEN and tears qemu down.
			// Other STOP reasons (paused-by-operator, watchdog, ...)
			// are ignored.
			runState := readQemuRunState(executorSocket)
			logrus.Infof("qmpEventHandler: STOP event runState=%q for %s", runState, domainName)
			if runState == "internal-error" {
				dumpPath := qemuTraceDir + domainName + ".guestmem.elf"
				if err := os.MkdirAll(qemuTraceDir, 0755); err != nil {
					logrus.Errorf("qmpEventHandler: mkdir %s failed: %v", qemuTraceDir, err)
				} else if err := execDumpGuestMemory(executorSocket, dumpPath); err != nil {
					logrus.Errorf("qmpEventHandler: dump-guest-memory failed for %s: %v", domainName, err)
				} else {
					logrus.Warnf("qmpEventHandler: guest memory dumped to %s (qemu now in RUN_STATE_INTERNAL_ERROR)", dumpPath)
				}
				// Pause-on-crash: read directly from the on-disk pubsub
				// publication of GlobalConfig (pillar maintains this at
				// /run/global/ConfigItemValueMap/global.json).  When
				// debug.qemu.pause.on.crash is true, leave qemu alive
				// so an operator can attach gdb / pull more dumps /
				// inspect VFIO state.  Pillar's outer loop still marks
				// the domain BROKEN.
				if readPauseOnCrashFlag() {
					logrus.Warnf("qmpEventHandler: pause-on-crash enabled, leaving qemu paused for %s (operator must clean up manually)", domainName)
				}
			}
		default:
			//Not handling the following events: RESUME, NIC_RX_FILTER_CHANGED, RTC_CHANGE, POWERDOWN
			logrus.Warnf("qmpEventHandler: Unhandled event: %s from QMP socket: %s", event.Event, listenerSocket)
		}
	}
	logrus.Infof("qmpEventHandler: Event channel closed for socket: %s (QMP connection lost)", listenerSocket)
}
