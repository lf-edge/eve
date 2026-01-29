package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPciLongExists(t *testing.T) {
	t.Skip("Skipping test dependent on host hardware capabilities/presence of PCI devices")
	testMatrix := map[string]struct {
		long string
		val  bool
	}{
		"Long value: 0000:ff:ff.f": {
			long: "0000:ff:ff.f",
			val:  false,
		},
		"Long value: 0000:00:00.0": {
			long: "0000:00:00.0",
			val:  true,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		output := pciLongExists(test.long)
		assert.Equal(t, test.val, output)
	}
}
