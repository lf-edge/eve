// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	pb "github.com/lf-edge/eve/evetest/grpcapi/go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const brokerStatusTimeout = 30 * time.Second

func brokerStatusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the broker version and its connected evetest clients",
		Long: `Show the broker version, its host, the EVE image uploads claimed with
"evetest broker image", and every evetest client session: the client's host
and CI job, the test it runs, the broker operation in progress for it, and its
devices. Sessions that are being closed are listed with the operation "Close"
until their devices are torn down.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			client, conn, err := dialBroker()
			if err != nil {
				return err
			}
			defer func() {
				if closeErr := conn.Close(); closeErr != nil {
					log.Warnf("failed to close the broker connection: %v", closeErr)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), brokerStatusTimeout)
			defer cancel()
			resp, err := client.GetStatus(ctx, &pb.GetStatusRequest{})
			if err != nil {
				return fmt.Errorf("failed to get the broker status: %w", err)
			}
			if asJSON {
				out, err := protojson.MarshalOptions{Multiline: true}.Marshal(resp)
				if err != nil {
					return fmt.Errorf("failed to marshal the broker status: %w", err)
				}
				fmt.Println(string(out))
				return nil
			}
			printBrokerStatus(os.Stdout, resp, time.Now())
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the status as JSON")
	return cmd
}

func printBrokerStatus(w io.Writer, resp *pb.GetStatusResponse, now time.Time) {
	maxClients := "unlimited"
	if resp.MaxClients >= 0 {
		maxClients = fmt.Sprint(resp.MaxClients)
	}
	_, _ = fmt.Fprintf(w, "Broker %s (%s provider), up %s, %d client session(s) (max %s)\n",
		resp.BrokerVersion, resp.Provider, since(now, resp.StartedAt), len(resp.Sessions), maxClients)
	printHostStatus(w, resp)
	printImageUploads(w, resp, now)

	for _, s := range resp.Sessions {
		_, _ = fmt.Fprintf(w, "\nClient %s", s.ClientId)
		if s.PeerAddress != "" {
			_, _ = fmt.Fprintf(w, " from %s", s.PeerAddress)
		}
		_, _ = fmt.Fprintln(w)
		row := rowPrinter(w)
		printClientInfo(row, s.GetClientInfo())
		connected := since(now, s.ConnectedAt) + " ago"
		if s.LastKeepAlive != nil {
			connected += ", last keep-alive " + since(now, s.LastKeepAlive) + " ago"
		}
		row("Connected", connected)
		row("Test", s.CurrentTest)
		if s.Operation != "" {
			row("Operation", fmt.Sprintf("%s (for %s)", s.Operation, since(now, s.OperationStartedAt)))
		}
		if len(s.Devices) == 0 {
			row("Devices", "none")
			continue
		}
		_, _ = fmt.Fprintln(w, "  Devices:")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "    NAME\tVM\tCREATED\tARCH\tCPUS\tMEMORY\tIMAGE")
		for _, d := range s.Devices {
			created := "no"
			if d.Created {
				created = "yes"
			}
			_, _ = fmt.Fprintf(tw, "    %s\t%s\t%s\t%s\t%s\t%s\t%s\n", d.Name, d.VmName, created,
				archName(d.Arch), orDash(d.Cpus), memory(d.MemoryBytes), d.Image)
		}
		_ = tw.Flush()
	}
}

func printHostStatus(w io.Writer, resp *pb.GetStatusResponse) {
	if resp.HostError != "" {
		_, _ = fmt.Fprintf(w, "\nHost: unavailable: %s\n", resp.HostError)
		return
	}
	h := resp.GetHost()
	if h == nil {
		return
	}
	_, _ = fmt.Fprintf(w, "\nHost %s", h.Name)
	if h.Description != "" {
		_, _ = fmt.Fprintf(w, " (%s)", h.Description)
	}
	_, _ = fmt.Fprintln(w)
	row := func(label, value string) {
		if value != "" {
			_, _ = fmt.Fprintf(w, "  %-11s%s\n", label+":", value)
		}
	}

	var cpu []string
	if h.Cpus > 0 {
		cpu = append(cpu, fmt.Sprintf("%d CPUs", h.Cpus))
	}
	if h.CpuUsage != nil {
		cpu = append(cpu, fmt.Sprintf("%.0f%% used", h.GetCpuUsage()*100))
	}
	if len(h.LoadAverage) > 0 {
		loads := make([]string, len(h.LoadAverage))
		for i, l := range h.LoadAverage {
			loads[i] = fmt.Sprintf("%.2f", l)
		}
		cpu = append(cpu, "load "+strings.Join(loads, " "))
	}
	row("CPU", strings.Join(cpu, ", "))

	if h.MemoryTotalBytes > 0 {
		mem := fmt.Sprintf("%s of %s available", gib(h.MemoryAvailableBytes), gib(h.MemoryTotalBytes))
		if h.SwapTotalBytes > 0 {
			mem += fmt.Sprintf(", swap %s of %s used", gib(h.SwapUsedBytes), gib(h.SwapTotalBytes))
		}
		row("Memory", mem)
	}

	if h.Vms > 0 {
		vms := fmt.Sprintf("%d running of %d", h.VmsRunning, h.Vms)
		if h.VmsRunningMemoryBytes > 0 {
			vms += fmt.Sprintf(", %s assigned to running VMs", gib(h.VmsRunningMemoryBytes))
			if h.MemoryTotalBytes > 0 {
				vms += fmt.Sprintf(" (%.0f%% of host memory)",
					float64(h.VmsRunningMemoryBytes)/float64(h.MemoryTotalBytes)*100)
			}
		}
		row("VMs", vms)
	}

	for i, st := range h.Storages {
		label := ""
		if i == 0 {
			label = "Storage:"
		}
		name := st.Name
		if st.Usage != "" {
			name += " (" + st.Usage + ")"
		}
		_, _ = fmt.Fprintf(w, "  %-11s%s: %s of %s available\n",
			label, name, gib(st.AvailableBytes), gib(st.TotalBytes))
	}
}

// printImageUploads lists the uploads claimed with "evetest broker image",
// which run without a client session.
func printImageUploads(w io.Writer, resp *pb.GetStatusResponse, now time.Time) {
	if len(resp.ImageUploads) == 0 {
		return
	}
	for _, u := range resp.ImageUploads {
		_, _ = fmt.Fprintf(w, "\nImage upload %s", u.Image)
		if u.PeerAddress != "" {
			_, _ = fmt.Fprintf(w, " from %s", u.PeerAddress)
		}
		_, _ = fmt.Fprintln(w)
		row := rowPrinter(w)
		printClientInfo(row, u.GetClientInfo())
		var state string
		if u.UploadStartedAt != nil {
			progress := mib(u.LoadedBytes)
			if u.ArchiveSizeBytes > 0 {
				progress = fmt.Sprintf("%.0f%% (%s of %s)",
					float64(u.LoadedBytes)/float64(u.ArchiveSizeBytes)*100,
					mib(u.LoadedBytes), mib(u.ArchiveSizeBytes))
			}
			state = fmt.Sprintf("uploading for %s, %s loaded", since(now, u.UploadStartedAt), progress)
		} else {
			state = "fetching the image, upload not started"
		}
		row("State", state)
		claim := since(now, u.ClaimedAt) + " ago"
		if u.ExpiresAt != nil {
			claim += fmt.Sprintf(", lapses in %s", u.ExpiresAt.AsTime().Sub(now).Round(time.Second))
		}
		row("Claimed", claim)
	}
}

// rowPrinter returns a function that prints a labelled row of a client or
// image upload block, skipping empty values.
func rowPrinter(w io.Writer) func(label, value string) {
	return func(label, value string) {
		if value != "" {
			_, _ = fmt.Fprintf(w, "  %-11s%s\n", label+":", value)
		}
	}
}

// printClientInfo prints what a client reported about itself; nothing for an
// older client that reports nothing.
func printClientInfo(row func(label, value string), info *pb.ClientInfo) {
	row("Host", info.GetHostname())
	row("Evetest", info.GetEvetestVersion())
	if ci := info.GetCiRunUrl(); ci != "" {
		var details []string
		if job := info.GetCiJob(); job != "" {
			details = append(details, "job "+job)
		}
		if runner := info.GetCiRunner(); runner != "" {
			details = append(details, "runner "+runner)
		}
		if len(details) > 0 {
			ci += " (" + strings.Join(details, ", ") + ")"
		}
		row("CI", ci)
	}
}

func mib(bytes uint64) string {
	return fmt.Sprintf("%.1f MiB", float64(bytes)/(1<<20))
}

func gib(bytes uint64) string {
	return fmt.Sprintf("%.1f GiB", float64(bytes)/(1<<30))
}

func since(now time.Time, ts *timestamppb.Timestamp) string {
	if ts == nil {
		return "?"
	}
	return now.Sub(ts.AsTime()).Round(time.Second).String()
}

func archName(arch pb.ArchType) string {
	return strings.ToLower(strings.TrimPrefix(arch.String(), "ARCH_"))
}

// orDash prints zero as "-": SetupDevices sizes EVE devices, so their CPUs and
// memory are unknown until then.
func orDash(n uint32) string {
	if n == 0 {
		return "-"
	}
	return fmt.Sprint(n)
}

func memory(bytes uint64) string {
	if bytes == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1fGiB", float64(bytes)/(1<<30))
}
