// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

const (
	// EvePlatformFile contains the platform string that indicates evaluation mode
	EvePlatformFile = "/hostfs/etc/eve-platform"
	// EvaluationPlatformString is the string that must be present to indicate evaluation mode
	EvaluationPlatformString = "evaluation"
)

// IsEvaluationPlatform reads /etc/eve-platform and returns true if it contains "evaluation"
// Uses OS filesystem by default
func IsEvaluationPlatform() bool {
	return IsEvaluationPlatformFS(afero.NewOsFs())
}

// IsEvaluationPlatformFS reads /etc/eve-platform and returns true if it contains "evaluation"
// Accepts filesystem abstraction for testing
func IsEvaluationPlatformFS(fs afero.Fs) bool {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "utils", 0)

	content, err := afero.ReadFile(fs, EvePlatformFile)
	if err != nil {
		// If file doesn't exist or can't be read, not an evaluation platform
		log.Warnf("IsEvaluationPlatform: %s not found or unreadable: %v", EvePlatformFile, err)
		return false
	}

	platformStr := strings.TrimSpace(string(content))
	isEval := strings.Contains(platformStr, EvaluationPlatformString)
	log.Functionf("IsEvaluationPlatform: platform='%s' contains '%s': %t", platformStr, EvaluationPlatformString, isEval)
	return isEval
}
