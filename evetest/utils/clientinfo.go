// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"fmt"
	"os"

	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/spf13/viper"
)

// BrokerClientInfo identifies this client for "evetest broker status": its
// host and, when it runs in GitHub Actions, the run, job and runner.
func BrokerClientInfo(evetestVersion string) *api.ClientInfo {
	info := &api.ClientInfo{
		Hostname:       viper.GetString(constants.ClientHostnameEnv),
		EvetestVersion: evetestVersion,
		CiJob:          os.Getenv("GITHUB_JOB"),
		CiRunner:       os.Getenv("RUNNER_NAME"),
	}
	if info.Hostname == "" {
		info.Hostname, _ = os.Hostname()
	}
	server, repo, runID := os.Getenv("GITHUB_SERVER_URL"),
		os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_RUN_ID")
	if server != "" && repo != "" && runID != "" {
		info.CiRunUrl = fmt.Sprintf("%s/%s/actions/runs/%s", server, repo, runID)
		if attempt := os.Getenv("GITHUB_RUN_ATTEMPT"); attempt != "" {
			info.CiRunUrl += "/attempts/" + attempt
		}
	}
	return info
}
