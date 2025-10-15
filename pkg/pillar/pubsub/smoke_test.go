package pubsub_test

// This file is just a temporary smoke test to instantiate the SocketDriver and
// pubsub.New(), and ensure that all interfaces are met.
// It will be replaced shortly by real unit tests.

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/nkvdriver"
	"github.com/sirupsen/logrus"
)

func foo() {
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)
	driver := nkvdriver.NewNkvDriver("/tmp/nkv/nkv.sock", "")
	ps := pubsub.New(driver, logger, log)
	fmt.Println(ps)
}
