package cas

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteKubevirtMountpointsFile(t *testing.T) {
	cas := containerdCAS{}
	mountPoints := map[string]struct{}{
		"/media/floppy": {},
		"/media/cdrom":  {},
	}

	dname, err := os.MkdirTemp("", "prefix")

	if err != nil {
		t.Fatal(err)
	}

	err = cas.writeKubevirtMountpointsFile(mountPoints, dname)
	if err != nil {
		t.Fatal(err)
	}

	contentBytes, err := os.ReadFile(filepath.Join(dname, "mountPoints"))

	if err != nil {
		t.Fatal(err)
	}

	content := string(contentBytes)

	for mountPoint := range mountPoints {
		if !strings.Contains(content, mountPoint) {
			t.Fatalf("mountPoint %s is missing", mountPoint)
		}
	}

	os.RemoveAll(filepath.Join(dname, "mountPoints"))
}
