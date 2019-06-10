package types

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

type TestDeriveLedCounterMatrixEntry struct {
	ledCounter         int
	usableAddressCount int
	expectedValue      int
}

func TestDeriveLedCounter(t *testing.T) {
	log.Infof("TestLookupIoBundle: START\n")
	testMatrix := []TestDeriveLedCounterMatrixEntry{
		{ledCounter: 0, usableAddressCount: 0, expectedValue: 1},
		{ledCounter: 0, usableAddressCount: 1, expectedValue: 2},
		{ledCounter: 2, usableAddressCount: 1, expectedValue: 2},
		{ledCounter: 3, usableAddressCount: 1, expectedValue: 3},
	}
	for index := range testMatrix {
		entry := &testMatrix[index]
		expectedValue := DeriveLedCounter(entry.ledCounter, entry.usableAddressCount)
		if expectedValue != entry.expectedValue {
			t.Errorf("Test Entry Index %d Failed: Expected Counter: %d, Actual Counter: %d\n",
				index, entry.expectedValue, expectedValue)
		}
	}
	log.Infof("TestLookupIoBundle: DONE\n")
}
