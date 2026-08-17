// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"encoding/json"
	"fmt"
	"time"
)

// qmpTimeout bounds a whole QMP exchange: connect, handshake and one command.
const qmpTimeout = 20 * time.Second

// QMPCommand executes a QMP (QEMU Machine Protocol) command against the monitor
// of a running domain and returns the raw payload of the reply's "return" member.
//
// The monitor is a unix socket on the device, reached by tunnelling a
// direct-streamlocal channel over SSH, so nothing has to be installed on the
// device to use this.
//
// QMP is the authoritative source for facts about a running domain that cannot
// be recovered from the outside. The motivating example is which host thread
// serves which guest vCPU: QEMU only names its vCPU threads when started with
// debug-threads=on, and a domain's thread group also contains vhost_task helper
// threads that are indistinguishable from vCPU threads by name or by flags. So
// scanning /proc can show that some thread is pinned, but not which vCPU it
// belongs to; "query-cpus-fast" answers that directly.
//
// Note that a QEMU monitor socket serves one client at a time, and EVE itself
// connects to it briefly for its own operations (for example to pin vCPUs at
// domain start, or to change a VNC password). Calls here are short-lived, but a
// caller that polls should tolerate an occasional failure to connect rather
// than treat the first one as fatal.
func (d *EdgeDevice) QMPCommand(domainName, command string) (json.RawMessage, error) {
	socket := fmt.Sprintf("/run/hypervisor/kvm/%s/qmp", domainName)
	conn, err := d.DialViaSSH("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("failed to reach QMP socket %s: %w", socket, err)
	}
	defer func() { _ = conn.Close() }()

	// An SSH channel does not support deadlines -- x/crypto/ssh rejects
	// SetDeadline with "deadline not supported" -- so the exchange is bounded by
	// closing the connection from a timer instead, which makes a blocked read
	// fail immediately. Without this a hypervisor that never answers would hang
	// the caller indefinitely.
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-time.After(qmpTimeout):
			_ = conn.Close()
		case <-finished:
		}
	}()

	dec := json.NewDecoder(conn)

	// QEMU announces itself first, and refuses commands until capabilities
	// negotiation completes.
	var greeting struct {
		QMP json.RawMessage `json:"QMP"`
	}
	if err := dec.Decode(&greeting); err != nil {
		return nil, fmt.Errorf("failed to read QMP greeting: %w", err)
	}
	if greeting.QMP == nil {
		return nil, fmt.Errorf("unexpected first QMP message: not a greeting")
	}
	if _, err := qmpExecute(conn, dec, "qmp_capabilities"); err != nil {
		return nil, fmt.Errorf("QMP capabilities negotiation failed: %w", err)
	}
	return qmpExecute(conn, dec, command)
}

// qmpExecute sends one command and returns its reply payload, skipping any
// asynchronous events QEMU emits in between.
func qmpExecute(conn interface{ Write([]byte) (int, error) },
	dec *json.Decoder, command string) (json.RawMessage, error) {
	request, err := json.Marshal(map[string]string{"execute": command})
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(request); err != nil {
		return nil, fmt.Errorf("failed to send QMP command %q: %w", command, err)
	}

	for {
		var reply struct {
			Return json.RawMessage `json:"return"`
			Error  *struct {
				Class string `json:"class"`
				Desc  string `json:"desc"`
			} `json:"error"`
			Event string `json:"event"`
		}
		if err := dec.Decode(&reply); err != nil {
			return nil, fmt.Errorf("failed to read reply to QMP command %q: %w",
				command, err)
		}
		if reply.Event != "" {
			continue // asynchronous event, not our reply
		}
		if reply.Error != nil {
			return nil, fmt.Errorf("QMP command %q failed: %s: %s",
				command, reply.Error.Class, reply.Error.Desc)
		}
		return reply.Return, nil
	}
}

// QMPVCPU describes one guest vCPU as reported by the QMP "query-cpus-fast"
// command. ThreadID is the host thread serving that vCPU, which is what makes a
// vCPU's CPU affinity checkable in /proc.
type QMPVCPU struct {
	CPUIndex int    `json:"cpu-index"`
	ThreadID int    `json:"thread-id"`
	Target   string `json:"target"`
}

// QueryVCPUs returns the guest vCPUs of a domain and the host thread serving
// each, ordered by guest vCPU index.
func (d *EdgeDevice) QueryVCPUs(domainName string) ([]QMPVCPU, error) {
	payload, err := d.QMPCommand(domainName, "query-cpus-fast")
	if err != nil {
		return nil, err
	}
	var vcpus []QMPVCPU
	if err := json.Unmarshal(payload, &vcpus); err != nil {
		return nil, fmt.Errorf("failed to parse query-cpus-fast reply: %w", err)
	}
	// QEMU is not required to report them in index order.
	for i := 0; i < len(vcpus); i++ {
		for j := i + 1; j < len(vcpus); j++ {
			if vcpus[j].CPUIndex < vcpus[i].CPUIndex {
				vcpus[i], vcpus[j] = vcpus[j], vcpus[i]
			}
		}
	}
	return vcpus, nil
}
