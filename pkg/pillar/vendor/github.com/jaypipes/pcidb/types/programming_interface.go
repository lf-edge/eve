//
// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package types

// ProgrammingInterface is the PCI programming interface for a class of PCI
// devices
type ProgrammingInterface struct {
	// IS is the hex-encoded PCI_ID of the programming interface
	ID string `json:"id"`
	// Name is the common string name for the programming interface
	Name string `json:"name"`
}
