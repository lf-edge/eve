package types

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDeriveLedCounter(t *testing.T) {

	testMatrix := map[string]struct {
		ledCounter         int
		usableAddressCount int
		expectedValue      int
	}{
		"usableAddressCount is 0": {
			ledCounter:         0,
			usableAddressCount: 0,
			expectedValue:      1,
		},
		"ledCounter less than 2": {
			ledCounter:         0,
			usableAddressCount: 1,
			expectedValue:      2,
		},
		"ledCounter equals 2": {
			ledCounter:         2,
			usableAddressCount: 1,
			expectedValue:      2,
		},
		"ledCounter greater than 2": {
			ledCounter:         3,
			usableAddressCount: 1,
			expectedValue:      3,
		},
	}

	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		output := DeriveLedCounter(test.ledCounter, test.usableAddressCount)
		assert.Equal(t, test.expectedValue, output)
	}
}
