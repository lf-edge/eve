// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/lf-edge/eve/evetest/constants"
	pb "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

func sdnCommand() *cobra.Command {
	sdnCmd := &cobra.Command{
		Use:   "sdn",
		Short: "Commands for interacting with the SDN (network emulator)",
	}
	sdnCmd.AddCommand(
		sdnStatusCmd(),
		sdnNetModelCmd(),
		sdnConfigGraphCmd(),
		sdnLogsCmd(),
		sdnSSHCmd(),
	)
	return sdnCmd
}

func sdnStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Get SDN status and config errors",
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.SDNRequest{}
			resp, err := client.GetSDNStatus(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get SDN status: %w", err)
			}

			if len(resp.MgmtIps) > 0 {
				fmt.Println("SDN Management IPs:")
				for _, ip := range resp.MgmtIps {
					fmt.Printf("  - %s\n", ip)
				}
			}

			if len(resp.ConfigErrors) > 0 {
				fmt.Println("SDN Configuration Errors:")
				for _, err := range resp.ConfigErrors {
					fmt.Printf("  - Item: %s\n    Error: %s\n", err.ItemRef, err.ErrorMsg)
				}
			} else {
				fmt.Println("No SDN configuration errors.")
			}

			return nil
		},
	}
	return cmd
}

func sdnNetModelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "net-model",
		Short: "Print abstract network model maintained by SDN",
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.SDNRequest{}
			resp, err := client.GetSDNNetworkModel(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get SDN network model: %w", err)
			}

			// Marshal the network model to JSON for readable output
			jsonBytes, err := protojson.MarshalOptions{
				Multiline:       true,
				EmitUnpopulated: false,
			}.Marshal(resp.NetworkModel)
			if err != nil {
				return fmt.Errorf("failed to marshal network model to JSON: %w", err)
			}

			fmt.Println(string(jsonBytes))
			return nil
		},
	}
	return cmd
}

func sdnConfigGraphCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "graph",
		Short: "Print SDN config graph as Graphviz dot format",
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.SDNRequest{}
			resp, err := client.GetSDNConfigGraph(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get SDN config graph: %w", err)
			}
			fmt.Println(resp.ConfigGraphviz)
			return nil
		},
	}
	return cmd
}

func sdnLogsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Stream logs from SDN",
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.SDNRequest{}
			stream, err := client.StreamSDNLogs(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to stream SDN logs: %w", err)
			}
			for {
				logMsg, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("stream error: %w", err)
				}
				fmt.Println(logMsg.String())
			}
			return nil
		},
	}
	return cmd
}

// localSDNTunnel opens a local TCP listener on 127.0.0.1:0, dials a
// ConnectTunnelToSDN gRPC stream for each accepted connection, and bridges them
// bidirectionally. It returns the local port, a wait function (blocks until the
// first bridge completes), and a close function that shuts the listener down.
func localSDNTunnel(ctx context.Context) (
	localPort int, wait func() error, closeFn func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, func() error { return err }, func() {}
	}
	localPort = ln.Addr().(*net.TCPAddr).Port
	doneCh := make(chan error, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			doneCh <- nil // listener closed, not an error
			return
		}
		defer conn.Close()

		stream, err := client.ConnectTunnelToSDN(ctx)
		if err != nil {
			doneCh <- fmt.Errorf("ConnectTunnelToSDN: %w", err)
			return
		}
		if err := stream.Send(&pb.ConnectSSHTunnelToSDNRequest{
			Payload: &pb.ConnectSSHTunnelToSDNRequest_Connect{
				Connect: &pb.SDNRequest{},
			},
		}); err != nil {
			doneCh <- fmt.Errorf("send connect: %w", err)
			return
		}
		resp, err := stream.Recv()
		if err != nil || resp.GetConnected() == nil {
			doneCh <- fmt.Errorf("tunnel not established: %w", err)
			return
		}

		grpcPipe := utils.GrpcClientPipe[pb.ConnectSSHTunnelToSDNRequest, pb.ConnectSSHTunnelToSDNResponse]{
			MakeRequest: func(data []byte) *pb.ConnectSSHTunnelToSDNRequest {
				return &pb.ConnectSSHTunnelToSDNRequest{
					Payload: &pb.ConnectSSHTunnelToSDNRequest_Data{Data: data},
				}
			},
			Stream: stream,
		}
		connPipe := utils.ReadWriterPipe{
			PipeName: "local connection",
			RW:       conn,
			Buf:      make([]byte, os.Getpagesize()),
		}
		utils.RunPipeProxy(ctx, log.WithField("component", "sdn-tunnel"),
			"SDN tunnel", grpcPipe, connPipe)
		doneCh <- nil
	}()

	return localPort, func() error { return <-doneCh }, func() { ln.Close() }
}

func sdnSSHCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh",
		Short: "Establish SSH connection to SDN",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Write SDN SSH private key to a temporary file.
			keyFilepath, err := createTmpSSHKeyFile(constants.SDNSSHPrivateKey)
			if err != nil {
				return err
			}
			defer func() {
				_ = os.Remove(keyFilepath)
			}()

			localPort, wait, closeFn := localSDNTunnel(context.Background())
			defer closeFn()

			// Run the ssh command.
			sshArgs := []string{
				"-o", "IdentitiesOnly=yes",
				"-o", "ConnectTimeout=5",
				"-o", "StrictHostKeyChecking=no",
				"-o", "UserKnownHostsFile=/dev/null",
				"-i", keyFilepath,
				"-p", strconv.Itoa(localPort),
				"root@127.0.0.1",
			}
			sshArgs = append(sshArgs, args...)
			err = utils.RunCommandForeground("ssh", sshArgs, utils.SetThisProcessStdin())
			closeFn()
			_ = wait()
			if err != nil {
				return fmt.Errorf("ssh command failed: %w", err)
			}
			return nil
		},
	}
	return cmd
}
