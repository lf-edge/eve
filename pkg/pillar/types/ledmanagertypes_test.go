package types

import (
	"github.com/stretchr/testify/assert"
	"testing"
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
