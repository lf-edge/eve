// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func main() {
	debug := flag.Bool("debug", false, "Set Debug log level")
	port := flag.Uint("port", constants.DefaultSDNPort, "Port on which to listen")
	ip := flag.String("ip", "0.0.0.0", "IP address on which to listen")
	flag.Parse()

	log.SetFormatter(&log.JSONFormatter{})
	if *debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	log.SetReportCaller(true)

	agent := &agent{}
	if err := agent.init(); err != nil {
		log.Fatal(err)
	}

	listenAddr := net.JoinHostPort(*ip, fmt.Sprintf("%d", *port))
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}

	server := grpc.NewServer()
	api.RegisterSDNServer(server, agent)

	log.Infof("SDN gRPC server listening on %s", listenAddr)
	if err := server.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
