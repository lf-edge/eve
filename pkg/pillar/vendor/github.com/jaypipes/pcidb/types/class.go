//
// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package types

// Class is the PCI class
type Class struct {
	// ID is the hex-encoded PCI_ID for the device class
	ID string `json:"id"`
	// Name is the common string name for the class
	Name string `json:"name"`
	// Subclasses are any subclasses belonging to this class
	Subclasses []*Subclass `json:"subclasses"`
}
