// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	verifier "github.com/lf-edge/eve/pkg/pillar/cmd/verifier/lib"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func oneShotCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "single",
		Short: "Verify the digest of a single file, move to verified directory, and exit",
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger := log.New()
			baseLogger := base.NewSourceLogObject(logger, "verifier", 1)

			infile := cmd.Flag("infile").Value.String()
			digest := cmd.Flag("digest").Value.String()
			name := cmd.Flag("name").Value.String()
			mediaType := cmd.Flag("mediaType").Value.String()
			tmpID, err := uuid.NewV4()
			if err != nil {
				return err
			}
			v, err := verifier.NewVerifier(cmd.Flag("verifier-base-path").Value.String(), baseLogger)
			if err != nil {
				return err
			}
			logger.Infof("verifying %s with digest %s", infile, digest)
			size, verifierFilename, err := v.MarkObjectAsVerifying(
				infile, digest, mediaType,
				tmpID)
			if err != nil {
				return err
			}
			logger.Infof("found file of size %d, verifying in location %s", size, verifierFilename)

			if err := v.VerifyObjectSha(name, verifierFilename, digest); err != nil {
				return err
			}
			logger.Infof("verified %s", verifierFilename)
			logger.Infof("moving %s to verified directory", verifierFilename)
			verifiedLocation, err := v.MarkObjectAsVerified(verifierFilename, digest, mediaType, tmpID)
			if err != nil {
				return err
			}
			logger.Infof("moved %s to %s", verifierFilename, verifiedLocation)
			return nil
		},
	}
	flags := cmd.Flags()
	flags.String("infile", "", "The file to verify")
	flags.String("digest", "", "The digest to verify")
	flags.String("name", "", "The reference name for the file")
	flags.String("mediaType", "", "The media type of the file")
	flags.String("verifier-base-path", "/tmp/verifier", "The base path for the verifier, all actions will be performed relative to this path")
	_ = cmd.MarkFlagRequired("infile")
	_ = cmd.MarkFlagRequired("digest")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("mediaType")
	return cmd
}
