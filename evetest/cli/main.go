// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/lf-edge/eve/evetest/constants"
	pb "github.com/lf-edge/eve/evetest/grpcapi/go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// needsClientAnnotation marks the commands which talk to an evetest instance
// over gRPC; subcommands inherit it from their ancestors.
const needsClientAnnotation = "evetest/needs-client"

var (
	// version is set using "go build -ldflags", this here is just a fallback value.
	version = "v0.0.1"
	client  pb.EvetestClient
)

func main() {
	constants.InitViperConfig()
	var instanceFlag string
	var grpcClient *grpc.ClientConn

	rootCmd := &cobra.Command{
		Use:         "evetest",
		Short:       "evetest CLI for controlling and inspecting EVE test runs",
		Annotations: map[string]string{needsClientAnnotation: "root"},
		// Errors such as an unresolvable instance are not usage mistakes.
		SilenceUsage: true,
		// Connect to the instance only for commands which need it, so that
		// e.g. "evetest instances", "use" and "completion" work without one.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if !needsClient(cmd) {
				return nil
			}
			t, err := resolveTarget(instanceFlag)
			if err != nil {
				return err
			}
			grpcClient, err = newGrpcClient(t)
			if err != nil {
				return fmt.Errorf("failed to create gRPC client: %w", err)
			}
			client = pb.NewEvetestClient(grpcClient)
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if grpcClient != nil {
				_ = grpcClient.Close()
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("evetest CLI version:", version)
			req := &pb.StatusRequest{}
			resp, err := client.Status(context.Background(), req)
			if err != nil {
				log.Warnf("Failed to get evetest (backend) version: %v", err)
			} else {
				fmt.Println("evetest (backend) version:", resp.EvetestVersion)
			}
			cmd.Help()
		},
	}

	rootCmd.PersistentFlags().StringVarP(&instanceFlag, "instance", "i", "",
		"evetest instance to talk to: name, API port or number from \"evetest instances\" "+
			"(default: the one chosen with \"evetest use\", or the only running one)")

	for _, c := range []*cobra.Command{
		continueCmd(),
		exitCmd(),
		statusCmd(),
		eveCommand(),
		clusterCommand(),
		sdnCommand(),
	} {
		c.Annotations = map[string]string{needsClientAnnotation: "yes"}
		rootCmd.AddCommand(c)
	}
	rootCmd.AddCommand(
		instancesCommand(),
		useCommand(),
		logsCommand(&instanceFlag),
		stopCommand(&instanceFlag),
		runCommand(),
	)

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("error executing command: %v", err)
	}
}

// needsClient tells whether the command (or one of its ancestors) talks to an
// evetest instance.
func needsClient(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if _, ok := c.Annotations[needsClientAnnotation]; ok {
			// The root command only needs a client when run without arguments.
			return c.Annotations[needsClientAnnotation] != "root" || cmd == c
		}
	}
	return false
}

func newGrpcClient(t target) (*grpc.ClientConn, error) {
	return grpc.NewClient(
		t.hostPort(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
}

func continueCmd() *cobra.Command {
	var until string
	cmd := &cobra.Command{
		Use:   "continue",
		Short: "Continue test execution until a checkpoint, test completion, or failure",
		Run: func(cmd *cobra.Command, args []string) {
			req := &pb.ContinueRequest{UntilCheckpoint: until}
			_, err := client.Continue(context.Background(), req)
			if err != nil {
				log.Fatalf("Continue RPC failed: %v", err)
			}
			fmt.Println("Test continues")
		},
	}
	cmd.Flags().StringVarP(&until, "until", "u", "", "continue until this checkpoint")
	return cmd
}

func exitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "exit",
		Short: "Exit the test early",
		Run: func(cmd *cobra.Command, args []string) {
			req := &pb.ExitRequest{}
			_, err := client.Exit(context.Background(), req)
			if err != nil {
				log.Fatalf("Exit RPC failed: %v", err)
			}
			fmt.Println("Test exited")
		},
	}
}

func printEVEDevices(devices []*pb.EVEDeviceStatus) {
	if len(devices) == 0 {
		fmt.Println("No EVE devices found.")
		return
	}

	fmt.Println("EVE Devices:")
	for i, dev := range devices {
		spec := dev.Spec
		fmt.Printf("  Device #%d:\n", i+1)
		if spec != nil {
			fmt.Printf("    Name:         %s\n", spec.DeviceName)
			fmt.Printf("    CPUs:         %d\n", spec.Cpus)
			fmt.Printf("    Memory:       %.2f GiB\n", float64(spec.MemoryBytes)/(1<<30))
			fmt.Printf("    With TPM:     %t\n", spec.WithTpm)
		} else {
			fmt.Println("    Spec:         <none>")
		}
		fmt.Printf("    State:        %s\n", dev.State.String())

		// Interface runtime status + spec data
		if len(dev.Interfaces) == 0 {
			fmt.Println("    Interfaces:   none")
		} else {
			fmt.Println("    Interfaces:")
			for _, iface := range dev.Interfaces {
				fmt.Printf("      - Name:            %s\n", iface.LogicalLabel)

				if iface.MacAddress != "" {
					fmt.Printf("        MAC Address:     %s\n", iface.MacAddress)
				} else {
					fmt.Println("        MAC Address:     <unknown>")
				}

				fmt.Printf("        Up:              %v\n", iface.Up)

				if len(iface.IpAddresses) == 0 {
					fmt.Println("        IPs:             <none>")
				} else {
					fmt.Printf("        IPs:             %v\n", iface.IpAddresses)
				}
			}
		}

		// Image (from spec)
		if spec != nil && spec.Image != nil {
			fmt.Println("    Image:")
			fmt.Printf("      Repo:        %s\n", spec.Image.Repo)
			fmt.Printf("      Version:     %s\n", spec.Image.Version)
			fmt.Printf("      Hypervisor:  %s\n", spec.Image.Hypervisor.String())
			fmt.Printf("      Arch:        %s\n", spec.Image.Arch.String())
		} else {
			fmt.Println("    Image:         <none>")
		}

		fmt.Println()
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Get current test execution status",
		Run: func(cmd *cobra.Command, args []string) {
			req := &pb.StatusRequest{}
			resp, err := client.Status(context.Background(), req)
			if err != nil {
				log.Fatalf("Status RPC failed: %v", err)
			}
			fmt.Println("Running test:", resp.TestName)
			if resp.TestSuiteName != "" {
				fmt.Println("From test suite:", resp.TestSuiteName)
			}
			if resp.Paused {
				if resp.TestFailure != "" {
					fmt.Println("Test failed with:", resp.TestFailure)
				} else {
					fmt.Println("Paused at checkpoint:", resp.CurrentCheckpoint)
				}
			}
			printEVEDevices(resp.EveDevices)
		},
	}
}
