// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// checkIdleArg makes the broker binary, instead of serving, ask the broker
// running on this host whether it is idle (see runCheckIdle). The Proxmox
// broker auto-upgrade runs it with "docker exec" before restarting the broker,
// but only for an image with the checkIdleLabel (see Dockerfile.broker): an
// older broker binary would ignore the argument and start a second broker.
const checkIdleArg = "check-idle"

const checkIdleTimeout = 30 * time.Second

// closeOperation is the operation of a session whose devices are being torn
// down after the client closed it or stopped sending keep-alive pings.
const closeOperation = "Close"

// Exit codes of check-idle.
const (
	exitIdle      = 0
	exitBusy      = 1
	exitIdleError = 2
)

// runCheckIdle prints what keeps the broker busy and returns exitBusy, or
// returns exitIdle when nothing does, or exitIdleError if it cannot tell.
func runCheckIdle() int {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(viper.GetInt(constants.BrokerPortEnv)))
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create broker client for %s: %v\n", addr, err)
		return exitIdleError
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), checkIdleTimeout)
	defer cancel()
	resp, err := api.NewBrokerClient(conn).GetStatus(ctx, &api.GetStatusRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get the broker status: %v\n", err)
		return exitIdleError
	}
	reasons := busyReasons(resp)
	for _, r := range reasons {
		fmt.Println(r)
	}
	if len(reasons) > 0 {
		return exitBusy
	}
	return exitIdle
}

// busyReasons lists the work that a broker restart would break: client
// sessions, including those whose devices are being torn down, and claimed
// image uploads, which run without a session.
func busyReasons(resp *api.GetStatusResponse) []string {
	var reasons []string
	for _, s := range resp.Sessions {
		if s.Operation == closeOperation {
			reasons = append(reasons, fmt.Sprintf("session of client %s is being closed", s.ClientId))
		} else {
			reasons = append(reasons, fmt.Sprintf("client %s is connected", s.ClientId))
		}
	}
	for _, u := range resp.ImageUploads {
		if u.UploadStartedAt != nil {
			reasons = append(reasons, fmt.Sprintf("image %s is being uploaded", u.Image))
		} else {
			reasons = append(reasons, fmt.Sprintf("a client claimed the upload of image %s", u.Image))
		}
	}
	return reasons
}
