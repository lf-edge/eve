//nolint:testpackage // TestNVMEIsUsed is a test function which requires access to unexported vars
package zfs

import (
	"os"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNVMEIsUsed(t *testing.T) {
	t.Parallel()
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 1234)
	var err error

	zfsManagerDir, err = os.MkdirTemp("./", "zfsmanager")
	if err != nil {
		t.Fatalf("unable to make %s directory: %v", zfsManagerDir, err)
	}
	defer os.RemoveAll(zfsManagerDir)

	// Init phase
	testMatrix := map[string]struct {
		pciIDs          []string
		devNames        []string // e.g., nvme0
		mountEntries    []string // e.g., /dev/nvme0p1 /mnt/nvme0p1 ext4 rw 0 0
		expectedAnswers []bool
	}{
		"Test empty": {},
		"falseDev": {
			pciIDs:          []string{"0000:00:00.0"},
			devNames:        []string{"nvme0"},
			mountEntries:    []string{""},
			expectedAnswers: []bool{false},
		},
	}

	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		for i, pciID := range test.pciIDs {
			assert.Equal(t, test.expectedAnswers[i], NVMEIsUsed(log, nil, pciID))
		}
	}
}
