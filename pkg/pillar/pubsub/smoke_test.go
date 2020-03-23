package pubsub_test

// This file is just a temporary smoke test to instantiate the SocketDriver and
// pubsub.New(), and ensure that all interfaces are met.
// It will be replaced shortly by real unit tests.

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
)

func foo() {
	driver := socketdriver.SocketDriver{}
	ps := pubsub.New(&driver)
	fmt.Println(ps)
}
