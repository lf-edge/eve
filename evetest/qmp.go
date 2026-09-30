// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"context"
	"encoding/json"
	"fmt"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

// ExecuteQMP runs one QMP command on the hypervisor running the device and
// returns the command's "return" member ("{}" for a command that returns
// nothing). arguments is marshaled into the command's "arguments" object: a
// map, a struct, or nil for a command without arguments. The test fails if the
// command is refused or cannot be delivered; see TryExecuteQMP for callers
// that expect refusals.
//
// Power control belongs to PowerOff, PowerOn and HardReboot, which keep the
// broker's view of the device in step; QMP commands such as quit or
// system_powerdown bypass that.
//
// Requires RequireCapabilities{CAPABILITY_QMP}.
func (d *EdgeDevice) ExecuteQMP(execute string, arguments any) json.RawMessage {
	ret, err := d.TryExecuteQMP(execute, arguments)
	if err != nil {
		d.th.t.Fatalf("ExecuteQMP: %v", err)
	}
	return ret
}

// TryExecuteQMP is ExecuteQMP returning the error instead of failing the test,
// for commands whose refusal is an expected outcome, e.g. blockdev-del while
// the node is still in use by a device being unplugged.
func (d *EdgeDevice) TryExecuteQMP(execute string, arguments any) (json.RawMessage, error) {
	req := &api.ExecuteQMPRequest{
		ClientId:   d.th.brokerClientID,
		DeviceName: d.devName,
		Execute:    execute,
	}
	if arguments != nil {
		argsJSON, err := json.Marshal(arguments)
		if err != nil {
			return nil, fmt.Errorf("QMP command %q on device %q: cannot marshal arguments: %w",
				execute, d.devName, err)
		}
		req.ArgumentsJson = string(argsJSON)
	}
	ctx, cancel := context.WithTimeout(d.th.ctx, brokerExecuteQMPTimeout)
	defer cancel()
	resp, err := d.th.brokerClient.ExecuteQMP(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("QMP command %q on device %q failed: %w",
			execute, d.devName, err)
	}
	return json.RawMessage(resp.GetReturnJson()), nil
}

// CreateScratchImage creates a blank, sparse raw disk image of the given size
// for the device on the hypervisor host and returns its path there, for use
// in QMP commands such as blockdev-add. name identifies the image within the
// device for DeleteScratchImage; it must follow QEMU's id rules (a letter
// followed by up to 30 letters, digits, '-' or '_'), so that it can double as
// block node name and device id. The image is removed with the device at the
// latest.
//
// Requires RequireCapabilities{CAPABILITY_QMP}.
func (d *EdgeDevice) CreateScratchImage(name string, sizeBytes uint64) string {
	ctx, cancel := context.WithTimeout(d.th.ctx, brokerScratchImageTimeout)
	defer cancel()
	resp, err := d.th.brokerClient.CreateScratchImage(ctx, &api.CreateScratchImageRequest{
		ClientId:   d.th.brokerClientID,
		DeviceName: d.devName,
		Name:       name,
		SizeBytes:  sizeBytes,
	})
	if err != nil {
		d.th.t.Fatalf("CreateScratchImage: broker failed to create image %q for device %q: %v",
			name, d.devName, err)
	}
	return resp.GetHostPath()
}

// DeleteScratchImage removes an image created by CreateScratchImage.
func (d *EdgeDevice) DeleteScratchImage(name string) {
	if err := d.tryDeleteScratchImage(name); err != nil {
		d.th.t.Fatalf("DeleteScratchImage: %v", err)
	}
}

// tryDeleteScratchImage is DeleteScratchImage returning the error, for cleanup
// paths that are about to fail the test with a more telling message.
func (d *EdgeDevice) tryDeleteScratchImage(name string) error {
	ctx, cancel := context.WithTimeout(d.th.ctx, brokerScratchImageTimeout)
	defer cancel()
	_, err := d.th.brokerClient.DeleteScratchImage(ctx, &api.DeleteScratchImageRequest{
		ClientId:   d.th.brokerClientID,
		DeviceName: d.devName,
		Name:       name,
	})
	if err != nil {
		return fmt.Errorf("broker failed to delete scratch image %q of device %q: %w",
			name, d.devName, err)
	}
	return nil
}
