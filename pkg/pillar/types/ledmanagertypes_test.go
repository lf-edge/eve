package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeriveLedCounter(t *testing.T) {

	testMatrix := map[string]struct {
		ledBlinkCount      LedBlinkCount
		usableAddressCount int
		radioSilence       bool
		expectedValue      LedBlinkCount
	}{
		"usableAddressCount is 0": {
			ledBlinkCount:      LedBlinkUndefined,
			usableAddressCount: 0,
			expectedValue:      LedBlinkWaitingForIP,
		},
		"ledBlinkCount less than 2 (without IP)": {
			ledBlinkCount:      LedBlinkUndefined,
			usableAddressCount: 1,
			expectedValue:      LedBlinkConnectingToController,
		},
		"ledBlinkCount is 2 (has IP)": {
			ledBlinkCount:      LedBlinkConnectingToController,
			usableAddressCount: 1,
			expectedValue:      LedBlinkConnectingToController,
		},
		"ledBlinkCount is greater than 2 (connected)": {
			ledBlinkCount:      LedBlinkConnectedToController,
			usableAddressCount: 1,
			expectedValue:      LedBlinkConnectedToController,
		},
		"radio silence is imposed (no usable addresses)": {
			ledBlinkCount:      LedBlinkUndefined,
			usableAddressCount: 0,
			radioSilence:       true,
			expectedValue:      LedBlinkRadioSilence,
		},
		"radio silence is imposed (have usable addresses)": {
			ledBlinkCount:      LedBlinkConnectedToController,
			usableAddressCount: 12,
			radioSilence:       true,
			expectedValue:      LedBlinkRadioSilence,
		},
	}

	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		output := DeriveLedCounter(test.ledBlinkCount, test.usableAddressCount, test.radioSilence)
		assert.Equal(t, test.expectedValue, output)
	}
}

// LedBlinkCount.String — all named cases and the default

func TestLedBlinkCountString(t *testing.T) {
	cases := []struct {
		c    LedBlinkCount
		want string
	}{
		{LedBlinkUndefined, "Undefined LED counter"},
		{LedBlinkWaitingForIP, "Waiting for DHCP IP address(es)"},
		{LedBlinkConnectingToController, "Trying to connect to EV Controller"},
		{LedBlinkConnectedToController, "Connected to EV Controller but not onboarded"},
		{LedBlinkOnboarded, "Connected to EV Controller and onboarded"},
		{LedBlinkRadioSilence, "Radio silence is imposed"},
		{LedBlinkOnboardingFailure, "Onboarding failure - generic"},
		{LedBlinkOnboardingFailureConflict, "Onboarding failure due to conflict with another device"},
		{LedBlinkOnboardingFailureNotFound, "Onboarding failure due to not being found in the controller"},
		{LedBlinkRespWithoutTLS, "Response without TLS - ignored"},
		{LedBlinkRespWithoutOSCP, "Response without OSCP or bad OSCP - ignored"},
		{LedBlinkInvalidControllerCert, "Failed to fetch or verify EV Controller certificate"},
		{LedBlinkInvalidAuthContainer, "Response has invalid controller signature"},
		{LedBlinkInvalidBootstrapConfig, "Invalid Bootstrap configuration"},
		{LedBlinkCount(99), fmt.Sprintf("Unsupported LED counter (%d)", 99)},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.c.String())
	}
}
