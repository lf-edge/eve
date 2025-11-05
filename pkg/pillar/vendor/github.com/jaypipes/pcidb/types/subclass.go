//
// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package types

// Subclass is a subdivision of a PCI class
type Subclass struct {
	// ID is the hex-encoded PCI_ID for the device subclass
	ID string `json:"id"`
	// Name is the common string name for the subclass
	Name string `json:"name"`
	// ProgrammingInterfaces contains any programming interfaces this subclass
	// might have
	ProgrammingInterfaces []*ProgrammingInterface `json:"programming_interfaces"`
}
