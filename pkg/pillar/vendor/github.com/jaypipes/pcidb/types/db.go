//
// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package types

type DB struct {
	// Classes is a map, keyed by class ID, of PCI Class information
	Classes map[string]*Class `json:"classes"`
	// Vendors is a map, keyed by vendor ID, of PCI Vendor information
	Vendors map[string]*Vendor `json:"vendors"`
	// Products is a map, keyed by vendor ID + product ID, of PCI product
	// information
	Products map[string]*Product `json:"products"`
}
