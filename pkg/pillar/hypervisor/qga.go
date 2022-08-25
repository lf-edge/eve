// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/mdlayher/vsock"
)

// SendCommandForQGA send cmd in application for qemu-guest-agent.
//
// Returns echo from cmd from application or error
func SendCommandForQGA(connection *vsock.Conn, qaCommand string) ([]byte, error) {
	var resBytes []byte
	bufSizeoff := 4096 // 4kb
	if _, err := connection.Write([]byte(qaCommand)); err != nil {
		return resBytes, fmt.Errorf(
			"send command %s for application with failed. "+
				"Error: %w", qaCommand, err)
	}

	response := make([]byte, bufSizeoff)
	if _, err := connection.Read(response); err != nil {
		return resBytes, err
	}

	for _, char := range response {
		if char != 0 {
			resBytes = append(resBytes, char)
		}
	}

	return resBytes, nil
}

// GuestSync кeturns error if having problems with synchronization or
// connection to app. And returns nil if all right
func GuestSync(connection *vsock.Conn) error {
	// Here we generate a random number to send it along with
	// the command and receive the same number from
	// the application if the synchronization was successful
	uid, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return err
	}

	cmd := fmt.Sprintf(
		`{"execute":"guest-sync", "arguments":{"id":%d}}`, uid.Int64())

	response, err := SendCommandForQGA(connection, cmd)
	if err != nil {
		return err
	}

	var jsonRes struct {
		UID int64 `json:"return"`
	}

	if err := json.Unmarshal(response, &jsonRes); err != nil {
		return fmt.Errorf("invalid JSON input: %w", err)
	}

	if jsonRes.UID != uid.Int64() {
		return fmt.Errorf("out of sync")
	}

	return nil
}

// GuestFsfreezeStatus - get guest fsfreeze state.
//
// Returns: GuestFsfreezeStatus ("thawed", "frozen", etc., as defined below)
// or error.
func GuestFsfreezeStatus(cid, port uint32) (string, error) {
	connection, err := vsock.Dial(cid, port, nil)
	if err != nil {
		return "", fmt.Errorf("an attempt to connect to the application "+
			"with cid %d:%d failed. Error: %w", cid, port, err)
	}
	defer connection.Close()

	err = GuestSync(connection)
	if err != nil {
		return "", fmt.Errorf("sync with Application failed. %v", err)
	}

	response, err := SendCommandForQGA(connection,
		`{"execute":"guest-fsfreeze-status"}`)
	if err != nil {
		return "", err
	}

	var jsonRes struct {
		Status string `json:"return"`
	}

	if err := json.Unmarshal(response, &jsonRes); err != nil {
		return "", fmt.Errorf("invalid JSON input: %w", err)
	}

	return jsonRes.Status, nil
}

// GuestFsFreezeFreeze - sync and freeze all freezable, local
// guest filesystems. If this command succeeded, you may call
// GuestFsFreezeThaw() later to unfreeze.
//
// Note: On Windows, the command is implemented with the help of a
// Volume Shadow-copy Service DLL helper. The frozen state is limited
// for up to 10 seconds by VSS.
//
// Returns: Number of file systems currently frozen or error.
// On error, all filesystems will be thawed. If no filesystems are
// frozen as a result of this call,  then GuestFsfreezeStatus() will
// return "thawed" and calling GuestFsFreezeThaw() is not necessary.
func GuestFsFreezeFreeze(cid, port uint32) (int, error) {
	connection, err := vsock.Dial(cid, port, nil)
	if err != nil {
		return 0, fmt.Errorf("an attempt to connect to the application "+
			"with cid %d:%d failed. Error: %w", cid, port, err)
	}
	defer connection.Close()

	err = GuestSync(connection)
	if err != nil {
		return 0, fmt.Errorf("sync with Application failed. %w", err)
	}

	response, err := SendCommandForQGA(connection,
		`{"execute":"guest-fsfreeze-freeze"}`)
	if err != nil {
		return 0, err
	}

	var jsonRes struct {
		CountFs int `json:"return"`
	}

	if err := json.Unmarshal(response, &jsonRes); err != nil {
		return 0, fmt.Errorf("invalid JSON input: %w", err)
	}

	return jsonRes.CountFs, nil
}

// GuestFsFreezeThaw - unfreeze all frozen guest filesystems
//
// Returns: Number of file systems thawed by this call or error.
//
// Note: if return value does not match the previous call to
// GuestFsFreezeFreeze(), this likely means some freezable
// filesystems were unfrozen before this call, and that the
// filesystem state may have changed before issuing this command.
func GuestFsFreezeThaw(cid, port uint32) (int, error) {
	connection, err := vsock.Dial(cid, port, nil)
	if err != nil {
		return 0, fmt.Errorf("an attempt to connect to the application "+
			"with cid %d:%d failed. Error: %w", cid, port, err)
	}
	defer connection.Close()

	err = GuestSync(connection)
	if err != nil {
		return 0, fmt.Errorf("sync with Application failed. %w", err)
	}

	response, err := SendCommandForQGA(connection,
		`{"execute":"guest-fsfreeze-thaw"}`)
	if err != nil {
		return 0, err
	}

	var jsonRes struct {
		CountFs int `json:"return"`
	}

	if err := json.Unmarshal(response, &jsonRes); err != nil {
		return 0, fmt.Errorf("invalid JSON input: %w", err)
	}
	return jsonRes.CountFs, nil
}
