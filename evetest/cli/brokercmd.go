// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/lf-edge/eve/evetest/constants"
	pb "github.com/lf-edge/eve/evetest/grpcapi/go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	// Exit codes of "claim-upload" other than 0 (granted, ticket on stdout)
	// and 1 (failure): the broker already has the image, and, with
	// --wait=false, another client holds the claim.
	exitImagePresent   = 10
	exitImageClaimHeld = 11

	imageClaimPollInterval = 15 * time.Second
	imageUploadChunkBytes  = 1024 * 1024
	// imageUploadTimeout bounds one upload attempt of a 1-2 GB image.
	imageUploadTimeout = 45 * time.Minute
)

// brokerCommand groups commands that talk to the evetest-broker directly, not
// to a running evetest instance.
func brokerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "broker",
		Short: "Commands for staging EVE images on the evetest-broker",
		Long: `Commands for staging EVE container images on the evetest-broker, for CI jobs
that run many suites against the same freshly built image. They talk to the
broker at ` + constants.EnvPrefix + constants.BrokerAddressEnv + `:` + constants.EnvPrefix + constants.BrokerPortEnv + `
and need no running evetest instance.

The first job to need an image obtains a claim ("claim-upload" prints a ticket),
fetches the image and uploads it ("upload"); the other jobs wait inside
"claim-upload" until the image is there. Typical use:

  TICKET=$(evetest broker image claim-upload --repo R --version V --hypervisor kvm)
  case $? in
    0)  ... fetch the image archive ...
        evetest broker image upload --ticket "$TICKET" image.tar ;;
    10) ;; # the broker has the image already
    *)  exit 1 ;;
  esac`,
	}
	image := &cobra.Command{
		Use:   "image",
		Short: "Stage an EVE container image on the broker",
	}
	image.AddCommand(imageClaimCmd(), imageUploadCmd(), imageReleaseCmd())
	cmd.AddCommand(image)
	return cmd
}

// imageFlags identify one EVE container image, the way a test's device does.
type imageFlags struct {
	repo, version, hypervisor, arch string
}

func (f *imageFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.repo, "repo", viper.GetString(constants.EVERepoEnv),
		"EVE image repository, e.g. evebuild/pr ("+constants.EnvPrefix+constants.EVERepoEnv+")")
	cmd.Flags().StringVar(&f.version, "version", "", "EVE image version")
	cmd.Flags().StringVar(&f.hypervisor, "hypervisor", "kvm", "hypervisor flavor: kvm, k or xen")
	cmd.Flags().StringVar(&f.arch, "arch", "amd64", "architecture: amd64 or arm64")
	_ = cmd.MarkFlagRequired("version")
}

func (f *imageFlags) ref() (*pb.ImageRef, error) {
	ref := &pb.ImageRef{Repo: f.repo, Version: f.version}
	switch f.hypervisor {
	case "kvm":
		ref.Hypervisor = pb.HypervisorType_HV_KVM
	case "k":
		ref.Hypervisor = pb.HypervisorType_HV_KUBEVIRT
	case "xen":
		ref.Hypervisor = pb.HypervisorType_HV_XEN
	default:
		return nil, fmt.Errorf("unknown hypervisor %q", f.hypervisor)
	}
	switch f.arch {
	case "amd64":
		ref.Arch = pb.ArchType_ARCH_AMD64
	case "arm64":
		ref.Arch = pb.ArchType_ARCH_ARM64
	default:
		return nil, fmt.Errorf("unknown architecture %q", f.arch)
	}
	if ref.Repo == "" {
		return nil, errors.New("the image repository is not set")
	}
	return ref, nil
}

func dialBroker() (pb.BrokerClient, *grpc.ClientConn, error) {
	addr := viper.GetString(constants.BrokerAddressEnv)
	if addr == "" {
		return nil, nil, fmt.Errorf("the broker address is not set (%s%s)",
			constants.EnvPrefix, constants.BrokerAddressEnv)
	}
	hostPort := net.JoinHostPort(addr, strconv.Itoa(viper.GetInt(constants.BrokerPortEnv)))
	conn, err := grpc.NewClient(hostPort,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create broker client for %s: %w", hostPort, err)
	}
	return pb.NewBrokerClient(conn), conn, nil
}

func imageClaimCmd() *cobra.Command {
	var img imageFlags
	var wait bool
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "claim-upload",
		Short: "Wait until the broker has an EVE image or it is this client's turn to upload it",
		Long: `Ask the broker for the right to upload an EVE container image.

Exits 0 and prints the ticket only when this client is the one to fetch and
upload the image (use "upload --ticket"; the claim lapses after 60 minutes if
the upload does not start, and after 10 minutes without upload progress). Any
other outcome exits non-zero: ` + strconv.Itoa(exitImagePresent) + ` when the broker already has the image, so
that there is nothing to upload, and 1 on a failure, including running out of
time waiting. While another client holds the claim, waits and asks again, taking
over if that client fails; with --wait=false it exits ` + strconv.Itoa(exitImageClaimHeld) + ` instead. Messages
and errors go to stderr; stdout carries only the ticket.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			ref, err := img.ref()
			if err != nil {
				return err
			}
			broker, conn, err := dialBroker()
			if err != nil {
				return err
			}
			defer func() {
				if closeErr := conn.Close(); closeErr != nil {
					log.Warnf("failed to close the broker connection: %v", closeErr)
				}
			}()
			ticket, held, err := claimImage(cmd.Context(), broker, ref, wait, timeout)
			if err != nil {
				return err
			}
			if held {
				fmt.Fprintln(os.Stderr, "another client holds the claim of the image")
				os.Exit(exitImageClaimHeld)
			}
			if ticket == "" {
				fmt.Fprintln(os.Stderr, "the broker already has the image, nothing to upload")
				os.Exit(exitImagePresent)
			}
			fmt.Print(ticket)
			return nil
		},
	}
	img.register(cmd)
	cmd.Flags().BoolVar(&wait, "wait", true, "wait while another client holds the claim")
	cmd.Flags().DurationVar(&timeout, "timeout", 90*time.Minute,
		"give up waiting for the image after this long")
	return cmd
}

// claimImage returns the ticket for uploading the image, or an empty ticket
// when the broker has it. With wait false and the claim held, held is set.
func claimImage(ctx context.Context, broker pb.BrokerClient, ref *pb.ImageRef,
	wait bool, timeout time.Duration) (ticket string, held bool, err error) {
	deadline := time.Now().Add(timeout)
	for {
		callCtx, cancel := context.WithTimeout(ctx, time.Minute)
		resp, err := broker.ClaimEVEImageUpload(callCtx, &pb.ClaimEVEImageUploadRequest{Image: ref})
		cancel()
		switch {
		case status.Code(err) == codes.Unimplemented:
			return "", false, errors.New("this broker does not support staging EVE images " +
				"(ClaimEVEImageUpload is unimplemented); update the broker")
		case status.Code(err) == codes.InvalidArgument:
			return "", false, fmt.Errorf("the broker rejected the image: %w", err)
		case err != nil:
			// The broker may be restarting; a persistent failure ends at the deadline.
			log.Warnf("ClaimEVEImageUpload failed: %v", err)
		case resp.GetState() == pb.ImageUploadClaimState_IMAGE_UPLOAD_CLAIM_PRESENT:
			log.Info("The broker has the image")
			return "", false, nil
		case resp.GetState() == pb.ImageUploadClaimState_IMAGE_UPLOAD_CLAIM_GRANTED:
			log.Info("Granted the claim of the image, it has to be uploaded")
			return resp.GetTicket(), false, nil
		case resp.GetState() == pb.ImageUploadClaimState_IMAGE_UPLOAD_CLAIM_HELD:
			if !wait {
				return "", true, nil
			}
			log.Info("Another client is uploading the image, waiting...")
		default:
			return "", false, fmt.Errorf("unexpected claim state %v", resp.GetState())
		}
		if time.Now().Add(imageClaimPollInterval).After(deadline) {
			return "", false, fmt.Errorf("the image did not show up on the broker within %v", timeout)
		}
		select {
		case <-time.After(imageClaimPollInterval):
		case <-ctx.Done():
			return "", false, ctx.Err()
		}
	}
}

func imageUploadCmd() *cobra.Command {
	var ticket string
	cmd := &cobra.Command{
		Use:   "upload <docker-archive.tar>",
		Short: "Upload an EVE image archive to the broker with the ticket from claim-upload",
		Long: `Upload a docker image archive (as written by "docker save") for the image that
the ticket claims. The archive has to carry the tag the image is claimed under.
If the upload fails, the broker releases the claim, so that a waiting client
takes over right away.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			broker, conn, err := dialBroker()
			if err != nil {
				return err
			}
			defer func() {
				if closeErr := conn.Close(); closeErr != nil {
					log.Warnf("failed to close the broker connection: %v", closeErr)
				}
			}()
			return uploadImage(cmd.Context(), broker, ticket, args[0])
		},
	}
	cmd.Flags().StringVar(&ticket, "ticket", "", "ticket printed by claim-upload")
	_ = cmd.MarkFlagRequired("ticket")
	return cmd
}

func uploadImage(ctx context.Context, broker pb.BrokerClient, ticket, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			log.Warnf("failed to close %s: %v", path, closeErr)
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, imageUploadTimeout)
	defer cancel()
	stream, err := broker.PushEVEContainerImage(ctx)
	if err != nil {
		return err
	}
	err = stream.Send(&pb.PushImageChunk{Payload: &pb.PushImageChunk_Request{
		Request: &pb.PushImageRequest{ClaimTicket: ticket},
	}})
	if err != nil {
		return fmt.Errorf("failed to send the upload request: %w", err)
	}

	// The broker expects `docker save | gzip`.
	pr, pw := io.Pipe()
	counter := &countingReader{r: f}
	go func() {
		gz := gzip.NewWriter(pw)
		_, err := io.Copy(gz, counter)
		if err == nil {
			err = gz.Close()
		}
		pw.CloseWithError(err)
	}()
	defer func() {
		if closeErr := pr.Close(); closeErr != nil {
			log.Warnf("failed to close the upload pipe: %v", closeErr)
		}
	}()

	buf := make([]byte, imageUploadChunkBytes)
	nextPercent := int64(10)
	for {
		n, readErr := io.ReadFull(pr, buf)
		if n > 0 {
			sendErr := stream.Send(&pb.PushImageChunk{
				Payload: &pb.PushImageChunk_DataGzipChunk{DataGzipChunk: buf[:n]},
			})
			if sendErr != nil {
				// The broker ended the stream; its response says why.
				break
			}
			if percent := counter.n * 100 / max(st.Size(), 1); percent >= nextPercent {
				log.Infof("Uploading the image to the broker: %d%%", nextPercent)
				nextPercent += 10
			}
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("failed to read %s: %w", path, readErr)
		}
	}
	if _, err = stream.CloseAndRecv(); err != nil {
		return err
	}
	log.Info("The image was uploaded to the broker")
	return nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func imageReleaseCmd() *cobra.Command {
	var ticket string
	cmd := &cobra.Command{
		Use:   "release-claim",
		Short: "Give up the claim of an EVE image obtained with claim-upload",
		Long: `Give up a claim whose image could not be fetched, so that a waiting client
takes over right away instead of when the claim lapses. Succeeds for a claim
that is already released or was taken over.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			broker, conn, err := dialBroker()
			if err != nil {
				return err
			}
			defer func() {
				if closeErr := conn.Close(); closeErr != nil {
					log.Warnf("failed to close the broker connection: %v", closeErr)
				}
			}()
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Minute)
			defer cancel()
			_, err = broker.ReleaseEVEImageUploadClaim(ctx,
				&pb.ReleaseEVEImageUploadClaimRequest{Ticket: ticket})
			return err
		},
	}
	cmd.Flags().StringVar(&ticket, "ticket", "", "ticket printed by claim-upload")
	_ = cmd.MarkFlagRequired("ticket")
	return cmd
}
