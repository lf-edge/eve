// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package instances

import (
	"context"
	"net"
	"strconv"
	"time"

	pb "github.com/lf-edge/eve/evetest/grpcapi/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const stateTimeout = 2 * time.Second

// State asks the instance, which must run on this host, for what it is doing
// and returns a short description such as "running" or
// "paused (checkpoint config-applied)".
func State(inst Instance) string {
	conn, err := grpc.NewClient(net.JoinHostPort("localhost", strconv.Itoa(inst.Port)),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return "unknown"
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), stateTimeout)
	defer cancel()
	resp, err := pb.NewEvetestClient(conn).Status(ctx, &pb.StatusRequest{})
	if err != nil {
		return "unreachable"
	}
	state := "running"
	if resp.TestName != "" && resp.TestName != inst.Name {
		state += " " + resp.TestName
	}
	if resp.Paused {
		if resp.TestFailure != "" {
			state = "paused (test failed)"
		} else {
			state = "paused (checkpoint " + resp.CurrentCheckpoint + ")"
		}
	}
	return state
}

// Devices returns the names of the EVE devices of the instance, which must run
// on this host.
func Devices(inst Instance) ([]string, error) {
	conn, err := grpc.NewClient(net.JoinHostPort("localhost", strconv.Itoa(inst.Port)),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), stateTimeout)
	defer cancel()
	resp, err := pb.NewEvetestClient(conn).Status(ctx, &pb.StatusRequest{})
	if err != nil {
		return nil, err
	}
	var names []string
	for _, dev := range resp.EveDevices {
		if dev.Spec != nil && dev.Spec.DeviceName != "" {
			names = append(names, dev.Spec.DeviceName)
		}
	}
	return names, nil
}
