// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/evetest/constants"
	pb "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"google.golang.org/protobuf/encoding/protojson"
)

var eveDeviceName string

func eveCommand() *cobra.Command {
	eveCmd := &cobra.Command{
		Use:   "eve",
		Short: "Commands for interacting with EVE devices",
	}
	eveCmd.PersistentFlags().StringVarP(&eveDeviceName, "devicename", "d", "", "EVE device name")
	eveCmd.AddCommand(
		eveHardRebootCmd(),
		eveSoftRebootCmd(),
		eveConfigCmd(),
		eveInfoCmd(),
		eveMetricsCmd(),
		eveLogsCmd(),
		eveConsoleOutputCmd(),
		eveAppInfoCmd(),
		eveAppMetricsCmd(),
		eveAppLogsCmd(),
		eveAppFlowLogsCmd(),
		eveNIInfoCmd(),
		eveNIMetricsCmd(),
		eveCollectInfoCmd(),
		eveSSHCmd(),
		eveSCPCmd(),
		evePortFwdCmd(),
		eveConsoleCmd(),
		eveKubectlCmd(),
	)
	return eveCmd
}

// addTailFlag adds a --tail/-t flag to a command. When used without a value
// (e.g. --tail), it defaults to 1. When used with a value (e.g. --tail 5),
// it uses that value. When not used at all, tail is 0 (meaning print all).
func addTailFlag(cmd *cobra.Command, tail *int) {
	cmd.Flags().IntVarP(tail, "tail", "t", 0,
		"Print only the last N entries (default 1 if no value given)")
	cmd.Flags().Lookup("tail").NoOptDefVal = "1"
}

// tailEntries returns the last n elements from entries. If n <= 0 or n >= len,
// it returns all entries.
func tailEntries(entries []string, n int) []string {
	if n <= 0 || n >= len(entries) {
		return entries
	}
	return entries[len(entries)-n:]
}

func eveHardRebootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hard-reboot",
		Short: "Hard reboots the device",
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.EVEDeviceRequest{DeviceName: eveDeviceName}
			_, err := client.HardRebootEVEDevice(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to hard reboot device: %w", err)
			}
			fmt.Println("Hard reboot command sent.")
			return nil
		},
	}
}

func eveSoftRebootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "soft-reboot",
		Short: "Soft reboots the device",
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.EVEDeviceRequest{DeviceName: eveDeviceName}
			_, err := client.SoftRebootEVEDevice(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to soft reboot device: %w", err)
			}
			fmt.Println("Soft reboot command sent.")
			return nil
		},
	}
}

func eveConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Prints config submitted through the controller",
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.EVEDeviceRequest{DeviceName: eveDeviceName}
			resp, err := client.GetEVEConfig(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get EVE config: %w", err)
			}

			// Marshal the config to JSON for readable output
			jsonBytes, err := protojson.MarshalOptions{
				Multiline:       true,
				EmitUnpopulated: false,
			}.Marshal(resp.Config)
			if err != nil {
				return fmt.Errorf("failed to marshal device config to JSON: %w", err)
			}

			fmt.Println(string(jsonBytes))
			return nil
		},
	}
	return cmd
}

func eveInfoCmd() *cobra.Command {
	var follow bool
	var tail int
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Prints device info (HW specs, adapter info, etc.)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if tail > 0 && follow {
				return fmt.Errorf("--tail and --follow cannot be used together")
			}
			req := &pb.EVEDeviceStreamableRequest{
				DeviceName: eveDeviceName,
				Follow:     follow,
			}
			stream, err := client.GetEVEInfo(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get EVE info stream: %w", err)
			}
			var entries []string
			for {
				resp, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("stream error: %w", err)
				}
				if tail > 0 {
					entries = append(entries, resp.DeviceInfo.String())
				} else {
					fmt.Println(resp.DeviceInfo.String())
					fmt.Println()
				}
			}
			for _, e := range tailEntries(entries, tail) {
				fmt.Println(e)
				fmt.Println()
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow device info updates")
	addTailFlag(cmd, &tail)
	return cmd
}

func eveMetricsCmd() *cobra.Command {
	var follow bool
	var tail int
	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Prints device metrics",
		RunE: func(cmd *cobra.Command, args []string) error {
			if tail > 0 && follow {
				return fmt.Errorf("--tail and --follow cannot be used together")
			}
			req := &pb.EVEDeviceStreamableRequest{
				DeviceName: eveDeviceName,
				Follow:     follow,
			}
			stream, err := client.GetEVEMetrics(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get device metrics stream: %w", err)
			}
			var entries []string
			for {
				resp, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("stream error: %w", err)
				}
				if tail > 0 {
					entries = append(entries, resp.DeviceMetrics.String())
				} else {
					fmt.Println(resp.DeviceMetrics.String())
					fmt.Println()
				}
			}
			for _, e := range tailEntries(entries, tail) {
				fmt.Println(e)
				fmt.Println()
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow device metrics")
	addTailFlag(cmd, &tail)
	return cmd
}

func eveLogsCmd() *cobra.Command {
	var follow bool
	var tail int
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Prints all device logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			if tail > 0 && follow {
				return fmt.Errorf("--tail and --follow cannot be used together")
			}
			req := &pb.EVEDeviceStreamableRequest{
				DeviceName: eveDeviceName,
				Follow:     follow,
			}
			stream, err := client.GetEVELogs(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get device logs stream: %w", err)
			}
			var entries []string
			for {
				logMsg, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("stream error: %w", err)
				}
				var ts string
				if logMsg.Timestamp != nil {
					ts = logMsg.Timestamp.AsTime().UTC().Format("2006-01-02 15:04:05.000")
				}
				severity := strings.ToLower(logMsg.Severity.String())
				severity = strings.TrimPrefix(severity, "log_")
				line := fmt.Sprintf("%s|%s|%s| %s",
					ts, severity, logMsg.Source, logMsg.Message)
				if tail > 0 {
					entries = append(entries, line)
				} else {
					fmt.Println(line)
				}
			}
			for _, e := range tailEntries(entries, tail) {
				fmt.Println(e)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow logs")
	addTailFlag(cmd, &tail)
	return cmd
}

func eveConsoleOutputCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "console-output",
		Short: "Prints full EVE console output",
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.EVEDeviceRequest{DeviceName: eveDeviceName}
			resp, err := client.GetEVEConsoleOutput(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get console output: %w", err)
			}
			fmt.Println("EVE console output:")
			fmt.Println(resp.ConsoleOutput)
			return nil
		},
	}
	return cmd
}

func eveAppInfoCmd() *cobra.Command {
	var follow bool
	var tail int
	cmd := &cobra.Command{
		Use:   "app-info <app-name-OR-UUID>",
		Short: "Prints application info for the given app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if tail > 0 && follow {
				return fmt.Errorf("--tail and --follow cannot be used together")
			}
			appID := args[0]
			req := &pb.AppRequest{
				DeviceName:    eveDeviceName,
				AppNameOrUuid: appID,
				Follow:        follow,
			}
			stream, err := client.GetAppInfo(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get app info stream: %w", err)
			}
			var entries []string
			for {
				resp, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("stream error: %w", err)
				}
				if tail > 0 {
					entries = append(entries, resp.AppInfo.String())
				} else {
					fmt.Println(resp.AppInfo.String())
					fmt.Println()
				}
			}
			for _, e := range tailEntries(entries, tail) {
				fmt.Println(e)
				fmt.Println()
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow app info updates")
	addTailFlag(cmd, &tail)
	return cmd
}

func eveAppMetricsCmd() *cobra.Command {
	var follow bool
	var tail int
	cmd := &cobra.Command{
		Use:   "app-metrics <appname-OR-UUID>",
		Short: "Prints application metrics for the given app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if tail > 0 && follow {
				return fmt.Errorf("--tail and --follow cannot be used together")
			}
			appID := args[0]
			req := &pb.AppRequest{
				DeviceName:    eveDeviceName,
				AppNameOrUuid: appID,
				Follow:        follow,
			}
			stream, err := client.GetAppMetrics(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get app metrics stream: %w", err)
			}
			var entries []string
			for {
				resp, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("stream error: %w", err)
				}
				if tail > 0 {
					entries = append(entries, resp.AppMetrics.String())
				} else {
					fmt.Println(resp.AppMetrics.String())
					fmt.Println()
				}
			}
			for _, e := range tailEntries(entries, tail) {
				fmt.Println(e)
				fmt.Println()
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow app metrics")
	addTailFlag(cmd, &tail)
	return cmd
}

func eveAppLogsCmd() *cobra.Command {
	var follow bool
	var tail int
	cmd := &cobra.Command{
		Use:   "app-logs <appname-OR-UUID>",
		Short: "Prints logs received from the given app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if tail > 0 && follow {
				return fmt.Errorf("--tail and --follow cannot be used together")
			}
			appID := args[0]
			req := &pb.AppRequest{
				DeviceName:    eveDeviceName,
				AppNameOrUuid: appID,
				Follow:        follow,
			}
			stream, err := client.GetAppLogs(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get app logs stream: %w", err)
			}
			var entries []string
			for {
				logMsg, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("stream error: %w", err)
				}
				if tail > 0 {
					entries = append(entries, logMsg.String())
				} else {
					fmt.Println(logMsg.String())
				}
			}
			for _, e := range tailEntries(entries, tail) {
				fmt.Println(e)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow app logs")
	addTailFlag(cmd, &tail)
	return cmd
}

func eveAppFlowLogsCmd() *cobra.Command {
	var follow bool
	var tail int
	cmd := &cobra.Command{
		Use:   "flow-logs <app-name-OR-UUID>",
		Short: "Prints flow logs captured for the given application",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if tail > 0 && follow {
				return fmt.Errorf("--tail and --follow cannot be used together")
			}
			appID := args[0]
			req := &pb.AppRequest{
				DeviceName:    eveDeviceName,
				AppNameOrUuid: appID,
				Follow:        follow,
			}
			stream, err := client.GetAppFlowLogs(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get flow logs stream: %w", err)
			}
			var entries []string
			for {
				resp, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("stream error: %w", err)
				}
				var lines []string
				for _, ipFlow := range resp.IpFlows {
					lines = append(lines, fmt.Sprintf("IP flow: %s", ipFlow.String()))
				}
				for _, dnsReq := range resp.DnsRequests {
					lines = append(lines, fmt.Sprintf("DNS request: %s", dnsReq.String()))
				}
				entry := strings.Join(lines, "\n")
				if tail > 0 {
					entries = append(entries, entry)
				} else {
					fmt.Println(entry)
				}
			}
			for _, e := range tailEntries(entries, tail) {
				fmt.Println(e)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow flow logs")
	addTailFlag(cmd, &tail)
	return cmd
}

func eveNIInfoCmd() *cobra.Command {
	var follow bool
	var tail int
	cmd := &cobra.Command{
		Use:   "ni-info <ni-name-OR-UUID>",
		Short: "Prints network interface info",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if tail > 0 && follow {
				return fmt.Errorf("--tail and --follow cannot be used together")
			}
			niID := args[0]
			req := &pb.NIRequest{
				DeviceName:   eveDeviceName,
				NiNameOrUuid: niID,
				Follow:       follow,
			}
			stream, err := client.GetNIInfo(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get NI info stream: %w", err)
			}
			var entries []string
			for {
				resp, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("stream error: %w", err)
				}
				if tail > 0 {
					entries = append(entries, resp.NiInfo.String())
				} else {
					fmt.Println(resp.NiInfo.String())
					fmt.Println()
				}
			}
			for _, e := range tailEntries(entries, tail) {
				fmt.Println(e)
				fmt.Println()
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow NI info updates")
	addTailFlag(cmd, &tail)
	return cmd
}

func eveNIMetricsCmd() *cobra.Command {
	var follow bool
	var tail int
	cmd := &cobra.Command{
		Use:   "ni-metrics <ni-name-OR-UUID>",
		Short: "Prints network instance metrics",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if tail > 0 && follow {
				return fmt.Errorf("--tail and --follow cannot be used together")
			}
			niID := args[0]
			req := &pb.NIRequest{
				DeviceName:   eveDeviceName,
				NiNameOrUuid: niID,
				Follow:       follow,
			}
			stream, err := client.GetNIMetrics(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get NI metrics stream: %w", err)
			}
			var entries []string
			for {
				resp, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("stream error: %w", err)
				}
				if tail > 0 {
					entries = append(entries, resp.NiMetrics.String())
				} else {
					fmt.Println(resp.NiMetrics.String())
					fmt.Println()
				}
			}
			for _, e := range tailEntries(entries, tail) {
				fmt.Println(e)
				fmt.Println()
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow NI metrics")
	addTailFlag(cmd, &tail)
	return cmd
}

func eveCollectInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "collect-info",
		Short: "Collects info for troubleshooting",
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.EVEDeviceRequest{DeviceName: eveDeviceName}
			resp, err := client.CollectInfo(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to collect EVE info: %w", err)
			}
			fmt.Printf("EVE info is collected into %q\n", resp.ArtifactPath)
			return nil
		},
	}
}

// localEVETunnel opens a local TCP listener on 127.0.0.1:0, dials a
// ConnectTunnelToEVE gRPC stream for each accepted connection, and bridges them
// bidirectionally. It returns the local port, a wait function (blocks until the
// first bridge completes), and a close function that shuts the listener down.
func localEVETunnel(ctx context.Context, req *pb.EVETunnelConnect) (
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

		stream, err := client.ConnectTunnelToEVE(ctx)
		if err != nil {
			doneCh <- fmt.Errorf("ConnectTunnelToEVE: %w", err)
			return
		}
		if err := stream.Send(&pb.ConnectTunnelToEVERequest{
			Payload: &pb.ConnectTunnelToEVERequest_Connect{Connect: req},
		}); err != nil {
			doneCh <- fmt.Errorf("send connect: %w", err)
			return
		}
		resp, err := stream.Recv()
		if err != nil || resp.GetConnected() == nil {
			doneCh <- fmt.Errorf("tunnel not established: %w", err)
			return
		}

		grpcPipe := utils.GrpcClientPipe[pb.ConnectTunnelToEVERequest, pb.ConnectTunnelToEVEResponse]{
			MakeRequest: func(data []byte) *pb.ConnectTunnelToEVERequest {
				return &pb.ConnectTunnelToEVERequest{
					Payload: &pb.ConnectTunnelToEVERequest_Data{Data: data},
				}
			},
			Stream: stream,
		}
		connPipe := utils.ReadWriterPipe{
			PipeName: "local connection",
			RW:       conn,
			Buf:      make([]byte, os.Getpagesize()),
		}
		utils.RunPipeProxy(ctx, log.WithField("component", "eve-tunnel"),
			"EVE tunnel", grpcPipe, connPipe)
		doneCh <- nil
	}()

	return localPort, func() error { return <-doneCh }, func() { ln.Close() }
}

func eveSSHCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh [command args...]",
		Short: "SSH into EVE",
		RunE: func(cmd *cobra.Command, args []string) error {
			keyFilepath, err := createTmpSSHKeyFile(constants.EVESSHPrivateKey)
			if err != nil {
				return err
			}
			defer os.Remove(keyFilepath)

			localPort, wait, closeFn := localEVETunnel(context.Background(),
				&pb.EVETunnelConnect{DeviceName: eveDeviceName, TargetPort: 22})
			defer closeFn()

			var sshArgs []string
			sshArgs = append(sshArgs, utils.EveSSHCommonArgs...)
			sshArgs = append(sshArgs,
				"-i", keyFilepath,
				"-p", strconv.Itoa(localPort),
				"root@127.0.0.1",
			)
			sshArgs = append(sshArgs, args...)
			err = utils.RunCommandForeground("ssh", sshArgs, utils.SetThisProcessStdin())
			closeFn()
			if tunnelErr := wait(); err != nil && tunnelErr != nil {
				return tunnelErr
			}
			if err != nil {
				return fmt.Errorf("ssh command failed: %w", err)
			}
			return nil
		},
	}
	return cmd
}

func createTmpSSHKeyFile(sshKey string) (filepath string, err error) {
	keyFile, err := os.CreateTemp("", "ssh-key-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary SSH key file: %w", err)
	}

	// SSH requires private keys to not be world-readable.
	if err := keyFile.Chmod(0600); err != nil {
		keyFile.Close()
		_ = os.Remove(keyFile.Name())
		return "", fmt.Errorf("failed to chmod SSH key file: %w", err)
	}

	if _, err := keyFile.WriteString(sshKey); err != nil {
		keyFile.Close()
		_ = os.Remove(keyFile.Name())
		return "", fmt.Errorf("failed to write SSH key: %w", err)
	}

	if err := keyFile.Close(); err != nil {
		_ = os.Remove(keyFile.Name())
		return "", fmt.Errorf("failed to close SSH key file: %w", err)
	}
	return keyFile.Name(), nil
}

func eveSCPCmd() *cobra.Command {
	var fromDevice bool
	var toDevice bool
	cmd := &cobra.Command{
		Use:   "scp [--from-device|--to-device] <source-path> <dest-path>",
		Short: "SCP files from/to device",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			sourcePath := args[0]
			destPath := args[1]
			if fromDevice && toDevice {
				return fmt.Errorf("cannot specify both --from-device and --to-device")
			}
			if !fromDevice && !toDevice {
				// Default direction
				fromDevice = true
			}

			// Write EVE SSH private key to a temporary file.
			keyFilepath, err := createTmpSSHKeyFile(constants.EVESSHPrivateKey)
			if err != nil {
				return err
			}
			defer func() {
				_ = os.Remove(keyFilepath)
			}()

			localPort, wait, closeFn := localEVETunnel(context.Background(),
				&pb.EVETunnelConnect{DeviceName: eveDeviceName, TargetPort: 22})
			defer closeFn()

			var scpArgs []string
			scpArgs = append(scpArgs, utils.EveSSHCommonArgs...)
			scpArgs = append(scpArgs,
				"-i", keyFilepath,
				"-P", strconv.Itoa(localPort),
			)
			deviceAddr := "root@127.0.0.1"
			if fromDevice {
				// root@ip:/path -> local
				scpArgs = append(scpArgs,
					fmt.Sprintf("%s:%s", deviceAddr, sourcePath), destPath)
			} else {
				// local -> root@ip:/path
				scpArgs = append(scpArgs,
					sourcePath, fmt.Sprintf("%s:%s", deviceAddr, destPath))
			}
			err = utils.RunCommandForeground("scp", scpArgs)
			closeFn()
			if tunnelErr := wait(); err != nil && tunnelErr != nil {
				return tunnelErr
			}
			if err != nil {
				return fmt.Errorf("scp command failed: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&fromDevice, "from-device", "f", false,
		"Copy file from device (default)")
	cmd.Flags().BoolVarP(&toDevice, "to-device", "t", false,
		"Copy file to device")
	return cmd
}

func evePortFwdCmd() *cobra.Command {
	var interfaceName string
	cmd := &cobra.Command{
		Use:   "portfwd <source-port>:<target-port>",
		Short: "Forward a local TCP port to a port on the EVE device",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			parts := strings.SplitN(args[0], ":", 2)
			if len(parts) != 2 {
				return fmt.Errorf(
					"invalid port mapping %q, expected <source-port>:<target-port>",
					args[0])
			}
			sourcePort, err := strconv.Atoi(parts[0])
			if err != nil || sourcePort <= 0 || sourcePort > 65535 {
				return fmt.Errorf("invalid source port %q", parts[0])
			}
			targetPort, err := strconv.Atoi(parts[1])
			if err != nil || targetPort <= 0 || targetPort > 65535 {
				return fmt.Errorf("invalid target port %q", parts[1])
			}

			// Start a local listener on the source port.
			ln, err := net.Listen("tcp",
				net.JoinHostPort("127.0.0.1", parts[0]))
			if err != nil {
				return fmt.Errorf("failed to listen on localhost:%d: %w",
					sourcePort, err)
			}
			defer ln.Close()

			fmt.Printf("Forwarding localhost:%d -> EVE device port %d\n",
				sourcePort, targetPort)
			fmt.Println("Press Ctrl+C to stop.")

			tunnelReq := &pb.EVETunnelConnect{
				DeviceName:    eveDeviceName,
				TargetPort:    uint32(targetPort),
				InterfaceName: interfaceName,
			}
			for {
				localConn, err := ln.Accept()
				if err != nil {
					// Listener was closed (e.g. Ctrl+C).
					return nil
				}
				go func(c net.Conn) {
					defer c.Close()
					stream, err := client.ConnectTunnelToEVE(context.Background())
					if err != nil {
						fmt.Fprintf(os.Stderr, "ConnectTunnelToEVE: %v\n", err)
						return
					}
					if err := stream.Send(&pb.ConnectTunnelToEVERequest{
						Payload: &pb.ConnectTunnelToEVERequest_Connect{Connect: tunnelReq},
					}); err != nil {
						fmt.Fprintf(os.Stderr, "send connect: %v\n", err)
						return
					}
					resp, err := stream.Recv()
					if err != nil || resp.GetConnected() == nil {
						fmt.Fprintf(os.Stderr, "tunnel not established: %v\n", err)
						return
					}
					grpcPipe := utils.GrpcClientPipe[
						pb.ConnectTunnelToEVERequest, pb.ConnectTunnelToEVEResponse]{
						MakeRequest: func(data []byte) *pb.ConnectTunnelToEVERequest {
							return &pb.ConnectTunnelToEVERequest{
								Payload: &pb.ConnectTunnelToEVERequest_Data{Data: data},
							}
						},
						Stream: stream,
					}
					localPipe := utils.ReadWriterPipe{
						PipeName: "local connection",
						RW:       c,
						Buf:      make([]byte, os.Getpagesize()),
					}
					proxyLog := log.WithField("component", "portfwd")
					utils.RunPipeProxy(context.Background(), proxyLog,
						"portfwd", grpcPipe, localPipe)
				}(localConn)
			}
		},
	}
	cmd.Flags().StringVarP(&interfaceName, "interface", "i", "",
		"EVE interface logical label (e.g. eth0)")
	return cmd
}

func eveConsoleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "console",
		Short: "Connect to the EVE console",
		RunE: func(cmd *cobra.Command, args []string) error {
			stream, err := client.ConnectConsoleToEVE(context.Background())
			if err != nil {
				return fmt.Errorf("ConnectConsoleToEVE: %w", err)
			}
			if err := stream.Send(&pb.ConnectConsoleToEVERequest{
				Payload: &pb.ConnectConsoleToEVERequest_Connect{
					Connect: &pb.EVEDeviceRequest{DeviceName: eveDeviceName},
				},
			}); err != nil {
				return fmt.Errorf("send connect: %w", err)
			}
			resp, err := stream.Recv()
			if err != nil {
				return fmt.Errorf("receive console properties: %w", err)
			}
			props := resp.GetConnectReply()

			grpcPipe := utils.GrpcClientPipe[
				pb.ConnectConsoleToEVERequest, pb.ConnectConsoleToEVEResponse]{
				MakeRequest: func(data []byte) *pb.ConnectConsoleToEVERequest {
					return &pb.ConnectConsoleToEVERequest{
						Payload: &pb.ConnectConsoleToEVERequest_Data{Data: data},
					}
				},
				Stream: stream,
			}

			if props.GetTelnet() {
				return runConsoleViaTelnet(grpcPipe)
			}
			return runConsoleRaw(grpcPipe)
		},
	}
	return cmd
}

// runConsoleViaTelnet bridges the console gRPC stream to a local TCP port and
// hands it to a real telnet client, letting it negotiate the Telnet protocol
// with the remote end.
func runConsoleViaTelnet(grpcPipe utils.GrpcClientPipe[
	pb.ConnectConsoleToEVERequest, pb.ConnectConsoleToEVEResponse]) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start local console listener: %w", err)
	}
	localPort := ln.Addr().(*net.TCPAddr).Port
	doneCh := make(chan error, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			doneCh <- nil // listener closed
			return
		}
		defer conn.Close()

		connPipe := utils.ReadWriterPipe{
			PipeName: "local telnet connection",
			RW:       conn,
			Buf:      make([]byte, os.Getpagesize()),
		}
		utils.RunPipeProxy(context.Background(),
			log.WithField("component", "eve-console"),
			"EVE console", grpcPipe, connPipe)
		doneCh <- nil
	}()

	telnetArgs := []string{
		"127.0.0.1",
		strconv.Itoa(localPort),
	}
	err = utils.RunCommandForeground(
		"telnet", telnetArgs, utils.SetThisProcessStdin())
	ln.Close()
	_ = <-doneCh
	if err != nil {
		return fmt.Errorf("telnet command failed: %w", err)
	}
	return nil
}

// escapeKey ends an interactive raw console session when read from the local
// terminal (Ctrl-]), mirroring telnet's classic escape character since there
// is no Telnet protocol here to negotiate a proper detach sequence.
const escapeKey = 0x1d

// escapeReader forwards bytes read from r until it sees escapeKey, at which
// point it reports io.EOF instead of forwarding that byte (or anything read
// afterward).
type escapeReader struct {
	r         io.Reader
	triggered bool
}

func (e *escapeReader) Read(p []byte) (int, error) {
	if e.triggered {
		return 0, io.EOF
	}
	n, err := e.r.Read(p)
	if n > 0 {
		if idx := bytes.IndexByte(p[:n], escapeKey); idx >= 0 {
			e.triggered = true
			if idx == 0 {
				return 0, io.EOF
			}
			return idx, nil
		}
	}
	return n, err
}

// stdioReadWriter adapts the process's separate stdin/stdout streams to the
// single io.ReadWriter that ReadWriterPipe expects.
type stdioReadWriter struct {
	io.Reader
	io.Writer
}

// runConsoleRaw bridges the console gRPC stream directly to the local
// terminal, without any Telnet protocol negotiation. If stdin is an
// interactive terminal it is put into raw mode (no local echo or line
// buffering) so keystrokes pass through untouched for the remote side (which
// already echoes them back) to handle, and Ctrl-] detaches cleanly.
func runConsoleRaw(grpcPipe utils.GrpcClientPipe[
	pb.ConnectConsoleToEVERequest, pb.ConnectConsoleToEVEResponse]) error {
	var stdin io.Reader = os.Stdin
	stdinFd := int(os.Stdin.Fd())
	if term.IsTerminal(stdinFd) {
		oldState, err := term.MakeRaw(stdinFd)
		if err != nil {
			return fmt.Errorf("failed to set local terminal to raw mode: %w", err)
		}
		defer func() { _ = term.Restore(stdinFd, oldState) }()
		stdin = &escapeReader{r: os.Stdin}
		fmt.Fprint(os.Stderr, "Connected to EVE console. Press Ctrl-] to exit.\r\n")
	}

	stdioPipe := utils.ReadWriterPipe{
		PipeName: "local terminal",
		RW:       stdioReadWriter{Reader: stdin, Writer: os.Stdout},
		Buf:      make([]byte, os.Getpagesize()),
	}
	utils.RunPipeProxy(context.Background(),
		log.WithField("component", "eve-console"),
		"EVE console", grpcPipe, stdioPipe)
	return nil
}

func eveKubectlCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "kubectl [kubectl-args...]",
		Short:              "Run kubectl commands against the EVE device Kubernetes cluster",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// DisableFlagParsing passes all args raw, including inherited parent
			// persistent flags (-d/--devicename). Parse and strip them here.
			devName, kubectlArgs := extractDeviceFlag(args)

			// Write EVE SSH private key to a temporary file.
			keyFilepath, err := createTmpSSHKeyFile(constants.EVESSHPrivateKey)
			if err != nil {
				return err
			}
			defer func() {
				_ = os.Remove(keyFilepath)
			}()

			localPort, wait, closeFn := localEVETunnel(context.Background(),
				&pb.EVETunnelConnect{DeviceName: devName, TargetPort: 22})
			defer closeFn()

			var sshArgs []string
			// Allocate a remote PTY when stdin is a terminal so that
			// interactive kubectl commands (e.g. exec -it) work correctly.
			if fi, err := os.Stdin.Stat(); err == nil &&
				(fi.Mode()&os.ModeCharDevice) != 0 {
				sshArgs = append(sshArgs, "-t")
			}
			sshArgs = append(sshArgs, utils.EveSSHCommonArgs...)
			sshArgs = append(sshArgs,
				"-i", keyFilepath,
				"-p", strconv.Itoa(localPort),
				"root@127.0.0.1",
				"eve", "exec", "kube", "kubectl",
			)
			sshArgs = append(sshArgs, kubectlArgs...)
			err = utils.RunCommandForeground("ssh", sshArgs, utils.SetThisProcessStdin())
			closeFn()
			if tunnelErr := wait(); err != nil && tunnelErr != nil {
				return tunnelErr
			}
			if err != nil {
				return fmt.Errorf("kubectl command failed: %w", err)
			}
			return nil
		},
	}
}

// extractDeviceFlag removes -d/--devicename flags from args (added by cobra's
// parent persistent-flag passthrough when DisableFlagParsing is true) and
// returns the device name value and the remaining args.
func extractDeviceFlag(args []string) (devName string, remaining []string) {
	for i := 0; i < len(args); i++ {
		switch {
		case (args[i] == "-d" || args[i] == "--devicename") && i+1 < len(args):
			if devName == "" {
				devName = args[i+1]
			}
			i++
		case strings.HasPrefix(args[i], "--devicename="):
			if devName == "" {
				devName = strings.TrimPrefix(args[i], "--devicename=")
			}
		default:
			remaining = append(remaining, args[i])
		}
	}
	return devName, remaining
}
