package nim

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/dpcmanager"
	"github.com/sirupsen/logrus"
)

func createTestNim() *nim {
	var n nim

	dpcManager := dpcmanager.DpcManager{}
	n.dpcManager = &dpcManager
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "zedagent", 1234)
	n.Logger = logger
	n.Log = log

	return &n
}

func TestControllerDNSCacheIndexOutOfRange(t *testing.T) {
	// Regression test for bug introduced by switching to miekg/dns
	n := createTestNim()

	n.controllerDNSCache([]byte(""), []byte("1.1"), "")
}

func TestWriteHostsFile(t *testing.T) {
	n := createTestNim()

	dnsResponses := []devicenetwork.DNSResponse{
		{
			IP: []byte{1, 1, 1, 1},
		},
		{
			IP: []byte{1, 0, 0, 1},
		},
	}

	dnsName := "one.one.one.one"

	f, err := os.CreateTemp("", "writeHostsFile.*.etchosts")
	if err != nil {
		panic(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	n.writeHostsFileToDestination(dnsResponses, []byte{}, []byte(dnsName), f.Name())

	// reopen the file to be able to read what has been written by writeHostsFileToDestination; f.Seek(0, 0) unfortunately is not enough
	f, err = os.Open(f.Name())
	if err != nil {
		panic(err)
	}
	content, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}

	for _, dnsResponse := range dnsResponses {
		expectedContent := fmt.Sprintf("%s %s\n", dnsResponse.IP.String(), dnsName)
		if !strings.Contains(string(content), expectedContent) {
			t.Fatalf(
				"writing to hosts file failed, expected: '%s', got: '%s'",
				expectedContent,
				content,
			)
		}
	}
}
