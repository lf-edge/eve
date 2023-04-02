package nim

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/dpcmanager"
	"github.com/sirupsen/logrus"
	"testing"
)

func TestControllerDNSCacheIndexOutOfRange(t *testing.T) {
	// Regression test for bug introduced by switching to miekg/dns
	var n nim

	dpcManager := dpcmanager.DpcManager{}
	n.dpcManager = &dpcManager
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "zedagent", 1234)
	n.Logger = logger
	n.Log = log

	n.controllerDNSCache([]byte("/etc/hosts"), []byte("1.1"), "")
}
