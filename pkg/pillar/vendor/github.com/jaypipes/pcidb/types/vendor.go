//
// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package types

// Vendor provides information about a device vendor
type Vendor struct {
	// IS is the hex-encoded PCI_ID for the vendor
	ID string `json:"id"`
	// Name is the common string name of the vendor
	Name string `json:"name"`
	// Products contains all top-level devices for the vendor
	Products []*Product `json:"products"`
}
