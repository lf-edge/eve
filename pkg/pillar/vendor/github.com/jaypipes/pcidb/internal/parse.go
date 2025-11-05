//
// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package internal

import (
	"bufio"
	"io"
	"strings"

	"github.com/jaypipes/pcidb/types"
)

// FromReader reads the supplied io.ReadCloser representing a PCIIDS database
// file or gzipped database file and returns a populated pcidb.DB with parsed
// PCI product, vendor and class information.
func FromReader(
	f io.ReadCloser,
) *types.DB {
	defer f.Close()
	scanner := bufio.NewScanner(f)
	inClassBlock := false
	classes := make(map[string]*types.Class, 20)
	vendors := make(map[string]*types.Vendor, 200)
	products := make(map[string]*types.Product, 1000)
	subclasses := make([]*types.Subclass, 0)
	progIfaces := make([]*types.ProgrammingInterface, 0)
	var curClass *types.Class
	var curSubclass *types.Subclass
	var curProgIface *types.ProgrammingInterface
	vendorProducts := make([]*types.Product, 0)
	var curVendor *types.Vendor
	var curProduct *types.Product
	var curSubsystem *types.Product
	productSubsystems := make([]*types.Product, 0)
	for scanner.Scan() {
		line := scanner.Text()
		// skip comments and blank lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lineBytes := []rune(line)

		// Lines starting with an uppercase "C" indicate a PCI top-level class
		// dbrmation block. These lines look like this:
		//
		// C 02  Network controller
		if lineBytes[0] == 'C' {
			if curClass != nil {
				// finalize existing class because we found a new class block
				curClass.Subclasses = subclasses
				subclasses = make([]*types.Subclass, 0)
			}
			inClassBlock = true
			classID := string(lineBytes[2:4])
			className := string(lineBytes[6:])
			curClass = &types.Class{
				ID:         classID,
				Name:       className,
				Subclasses: subclasses,
			}
			classes[curClass.ID] = curClass
			continue
		}

		// Lines not beginning with an uppercase "C" or a TAB character
		// indicate a top-level vendor dbrmation block. These lines look like
		// this:
		//
		// 0a89  BREA Technologies Inc
		if lineBytes[0] != '\t' {
			if curVendor != nil {
				// finalize existing vendor because we found a new vendor block
				curVendor.Products = vendorProducts
				vendorProducts = make([]*types.Product, 0)
			}
			inClassBlock = false
			vendorID := string(lineBytes[0:4])
			vendorName := string(lineBytes[6:])
			curVendor = &types.Vendor{
				ID:       vendorID,
				Name:     vendorName,
				Products: vendorProducts,
			}
			vendors[curVendor.ID] = curVendor
			continue
		}

		// Lines beginning with only a single TAB character are *either* a
		// subclass OR are a device dbrmation block. If we're in a class
		// block (i.e. the last parsed block header was for a PCI class), then
		// we parse a subclass block. Otherwise, we parse a device dbrmation
		// block.
		//
		// A subclass dbrmation block looks like this:
		//
		// \t00  Non-VGA unclassified device
		//
		// A device dbrmation block looks like this:
		//
		// \t0002  PCI to MCA Bridge
		if len(lineBytes) > 1 && lineBytes[1] != '\t' {
			if inClassBlock {
				if curSubclass != nil {
					// finalize existing subclass because we found a new subclass block
					curSubclass.ProgrammingInterfaces = progIfaces
					progIfaces = make([]*types.ProgrammingInterface, 0)
				}
				subclassID := string(lineBytes[1:3])
				subclassName := string(lineBytes[5:])
				curSubclass = &types.Subclass{
					ID:                    subclassID,
					Name:                  subclassName,
					ProgrammingInterfaces: progIfaces,
				}
				subclasses = append(subclasses, curSubclass)
			} else {
				if curProduct != nil {
					// finalize existing product because we found a new product block
					curProduct.Subsystems = productSubsystems
					productSubsystems = make([]*types.Product, 0)
				}
				productID := string(lineBytes[1:5])
				productName := string(lineBytes[7:])
				productKey := curVendor.ID + productID
				curProduct = &types.Product{
					VendorID: curVendor.ID,
					ID:       productID,
					Name:     productName,
				}
				vendorProducts = append(vendorProducts, curProduct)
				products[productKey] = curProduct
			}
		} else {
			// Lines beginning with two TAB characters are *either* a subsystem
			// (subdevice) OR are a programming interface for a PCI device
			// subclass. If we're in a class block (i.e. the last parsed block
			// header was for a PCI class), then we parse a programming
			// interface block, otherwise we parse a subsystem block.
			//
			// A programming interface block looks like this:
			//
			// \t\t00  UHCI
			//
			// A subsystem block looks like this:
			//
			// \t\t0e11 4091  Smart Array 6i
			if inClassBlock {
				progIfaceID := string(lineBytes[2:4])
				progIfaceName := string(lineBytes[6:])
				curProgIface = &types.ProgrammingInterface{
					ID:   progIfaceID,
					Name: progIfaceName,
				}
				progIfaces = append(progIfaces, curProgIface)
			} else {
				vendorID := string(lineBytes[2:6])
				subsystemID := string(lineBytes[7:11])
				subsystemName := string(lineBytes[13:])
				curSubsystem = &types.Product{
					VendorID: vendorID,
					ID:       subsystemID,
					Name:     subsystemName,
				}
				productSubsystems = append(productSubsystems, curSubsystem)
			}
		}
	}
	return &types.DB{
		Classes:  classes,
		Products: products,
		Vendors:  vendors,
	}
}
