package types

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestIoBundleToPciRenamesShiftedIfname covers the app-direct release path: an
// assignable Ethernet port (model ifname "eth97", stable PciLong) returns from
// PCI passthrough under a kernel-shifted name ("eth98") — deleting an app frees
// a lower ethN index, so the kernel can give the returning NIC a different name
// than the model expects. IoBundleToPci must recognize this by the stable PCI
// address, rename the kernel interface back to the model name, and record the
// adjustment as an advisory ErrIoBundleRename warning for the controller. This
// path is not reachable end-to-end under QEMU (the reverse PCI->ifname sysfs
// lookup does not resolve there), so it is verified against a fabricated sysfs
// tree by redirecting basePath/pciPath.
func TestIoBundleToPciRenamesShiftedIfname(t *testing.T) {
	tmp := t.TempDir()
	origBase, origPci := basePath, pciPath
	basePath = filepath.Join(tmp, "net") // empty: the model ifname does not resolve
	pciPath = filepath.Join(tmp, "pci")
	defer func() { basePath, pciPath = origBase, origPci }()

	const (
		pci        = "0000:00:09.0"
		modelName  = "eth97" // name in the controller's model
		kernelName = "eth98" // shifted name the kernel now gives the returned NIC
	)
	// The stable PCI address currently backs the kernel-shifted interface name.
	require.NoError(t, os.MkdirAll(filepath.Join(pciPath, pci, "net", kernelName), 0o755))
	require.NoError(t, os.MkdirAll(basePath, 0o755))

	log := base.NewSourceLogObject(logrus.StandardLogger(), t.Name(), 0)
	ib := &IoBundle{
		Type:         IoNetEth,
		Phylabel:     modelName,
		Logicallabel: modelName,
		Ifname:       modelName,
		PciLong:      pci,
	}

	long, err := IoBundleToPci(log, ib)
	require.NoError(t, err)
	assert.Equal(t, pci, long)

	// The rename is reported as an advisory warning (not a hard error) that names
	// the shifted kernel interface EVE renamed back to the model.
	assert.True(t, ib.Error.IsOnlyWarnings(),
		"rename should be an advisory warning, got %q", ib.Error.String())
	assert.Contains(t, ib.Error.String(), "renamed to match the model")
	assert.Contains(t, ib.Error.String(), kernelName)
}
