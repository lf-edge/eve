// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lf-edge/eve/evetest/broker/provider"
	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

var (
	// version is set using "go build -ldflags", this here is just a fallback value.
	version = "v0.0.1"
)

func main() {
	constants.InitViperConfig()

	// Setup logging
	logLevelStr := viper.GetString(constants.LogLevelEnv)
	logLevel, err := logrus.ParseLevel(logLevelStr)
	if err != nil {
		logrus.Fatalf("Failed to parse log level %q: %v", logLevelStr, err)
	}
	log := logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
	})
	log.SetLevel(logLevel)
	log.Infof("Starting Evetest Broker version %q", version)

	// Start TCP listener for the gRPC API.
	port := viper.GetInt(constants.BrokerPortEnv)
	listenAddr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to start TCP listener: %v", err)
	}
	defer listener.Close()

	// Create user-selected device provider and pass it to the broker.
	commonProviderConf, err := provider.GetCommonProviderConf()
	if err != nil {
		log.Fatal(err)
	}
	providerName := viper.GetString(constants.BrokerProviderEnv)
	var deviceProvider provider.DeviceProvider
	switch providerName {
	case "libvirt":
		// Custom URI not yet supported.
		// uri := viper.GetString(constants.BrokerLibvirtURIEnv)

		conf := provider.LibvirtProviderConf{
			CommonProviderConf: commonProviderConf,
		}
		deviceProvider, err = provider.NewLibvirtProvider(conf)
		if err != nil {
			log.Fatalf("Failed to create libvirt device provider: %v", err)
		}
	case "qemu":
		conf := provider.QemuProviderConf{
			CommonProviderConf: commonProviderConf,
			ArtifactDir:        viper.GetString(constants.InternalArtifactDirEnv),
		}
		deviceProvider, err = provider.NewQemuProvider(conf)
		if err != nil {
			log.Fatalf("Failed to create qemu device provider: %v", err)
		}
	case "proxmox":
		conf := provider.ProxmoxProviderConf{
			CommonProviderConf: commonProviderConf,
			APIURL:             viper.GetString(constants.BrokerProxmoxAPIURLEnv),
			Password:           viper.GetString(constants.BrokerProxmoxPasswordEnv),
			Node:               viper.GetString(constants.BrokerProxmoxNodeEnv),
			Storage:            viper.GetString(constants.BrokerProxmoxStorageEnv),
			ImportStorage:      viper.GetString(constants.BrokerProxmoxImportStorageEnv),
			TLSSkipVerify:      viper.GetBool(constants.BrokerProxmoxTLSSkipVerifyEnv),
		}
		deviceProvider, err = provider.NewProxmoxProvider(conf)
		if err != nil {
			log.Fatalf("Failed to create proxmox device provider: %v", err)
		}
	default:
		log.Fatalf("Unsupported device provider: %q", providerName)
	}
	defer deviceProvider.Close()

	// Instantiate evetest broker.
	sdnGrpcPort := viper.GetUint16(constants.SDNPortEnv)
	imageDir := viper.GetString(constants.BrokerImageDirEnv)
	maxClients := viper.GetInt(constants.BrokerMaxClientsEnv)
	broker, err := newBroker(log, deviceProvider, providerName, imageDir, sdnGrpcPort, maxClients)
	if err != nil {
		log.Fatal(err)
	}
	server := grpc.NewServer()
	api.RegisterBrokerServer(server, broker)

	// Setup cleanup Go routine triggered on shutdown.
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-c
		log.Info("Shutting down...")
		server.Stop()
	}()

	// Run the gRPC service.
	log.Infof("Broker gRPC server listening on %s", listenAddr)
	if err := server.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
	log.Infof("Broker gRPC server exited")
	broker.CloseAll(context.Background())
	log.Info("CloseAll done.")
}
