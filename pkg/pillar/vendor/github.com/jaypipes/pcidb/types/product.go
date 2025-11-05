//
// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package types

// Product provides information about a PCI device model.
//
// In the hardware world, the PCI "device_id" is the identifier for the
// product/model
type Product struct {
	// VendorID is the vendor ID for the product
	VendorID string `json:"vendor_id"`
	// ID is the hex-encoded PCI_ID for the product/model
	ID string `json:"id"`
	// Name is the common string name of the vendor
	Name string `json:"name"`
	// Subsystems contains "subdevices" or "subsystems" for the product
	Subsystems []*Product `json:"subsystems"`
}
