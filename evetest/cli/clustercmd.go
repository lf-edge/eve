// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"

	pb "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/spf13/cobra"
)

func clusterCommand() *cobra.Command {
	clusterCmd := &cobra.Command{
		Use:   "cluster",
		Short: "Commands for interacting with the cluster of EVE devices",
	}
	clusterCmd.AddCommand(
		clusterInfoCmd(),
		clusterUpdateInfoCmd(),
		clusterMetricsCmd(),
	)
	return clusterCmd
}

func clusterInfoCmd() *cobra.Command {
	var follow bool
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Prints cluster info",
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.ClusterRequest{Follow: follow}
			stream, err := client.GetClusterInfo(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get EVE cluster info stream: %w", err)
			}
			for {
				resp, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("stream error: %w", err)
				}
				fmt.Printf("[%s] %s\n", resp.FromNode, resp.ClusterInfo.String())
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow cluster info updates")
	return cmd
}

func clusterUpdateInfoCmd() *cobra.Command {
	var follow bool
	cmd := &cobra.Command{
		Use:   "update-info",
		Short: "Prints cluster update status info",
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.ClusterRequest{Follow: follow}
			stream, err := client.GetClusterUpdateInfo(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get cluster update info stream: %w", err)
			}
			for {
				resp, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("stream error: %w", err)
				}
				fmt.Printf("[%s] %s\n", resp.FromNode, resp.ClusterUpdateInfo.String())
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow cluster update info")
	return cmd
}

func clusterMetricsCmd() *cobra.Command {
	var follow bool
	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Prints cluster metrics",
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.ClusterRequest{Follow: follow}
			stream, err := client.GetClusterMetrics(context.Background(), req)
			if err != nil {
				return fmt.Errorf("failed to get cluster metrics stream: %w", err)
			}
			for {
				resp, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("stream error: %w", err)
				}
				fmt.Printf("[%s] %s\n", resp.FromNode, resp.ClusterMetrics.String())
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow cluster metrics updates")
	return cmd
}
