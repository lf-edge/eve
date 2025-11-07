package inventory

import "testing"

func TestCreateInventory(t *testing.T) {

	inventory, err := CreateInventory()
	if err != nil {
		panic(err)
	}

	t.Log(inventory)
}
