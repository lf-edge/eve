package hardware

import (
	"testing"

	"github.com/lf-edge/eve-api/go/info"
)

func TestCreateInventory(t *testing.T) {

	msg := info.ZInfoHardware{}
	err := AddInventoryInfo(&msg)
	if err != nil {
		panic(err)
	}

	t.Log(&msg)
}
