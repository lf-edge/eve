package types

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestpciLongExists(t *testing.T) {
	testMatrix := map[string]struct {
		long string
		val  bool
	}{
		"Long value: 0000:03:00.0": {
			long: "0000:03:00.0",
			val:  true,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		output := pciLongExists(test.long)
		assert.Equal(t, test.val, output)
	}
}
