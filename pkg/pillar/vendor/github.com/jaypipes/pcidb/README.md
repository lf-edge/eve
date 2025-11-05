# `pcidb` - the Golang PCI DB library

[![Build Status](https://github.com/jaypipes/pcidb/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/jaypipes/pcidb/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/jaypipes/pcidb)](https://goreportcard.com/report/github.com/jaypipes/pcidb)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

`pcidb` is a small Go library for programmatic querying of PCI vendor, product
and class information.

We test `pcidb` on Linux, Windows and MacOSX.

## Usage

`pcidb` contains a PCI database inspection and querying facility that allows
developers to query for information about hardware device classes, vendor and
product information.

The `pcidb.New()` function returns a `pcidb.PCIDB` struct or an error if the
PCI database could not be loaded.

```go
package main

import (
    "fmt"

    "github.com/jaypipes/pcidb"
)

func main() {
    pci, err := pcidb.New()
    if err != nil {
        fmt.Printf("Error getting PCI info: %v", err)
    }
}
```

> Learn about [how `pcidb` discovers `pci.ids` database files](#discovery).

The `pcidb.PCIDB` struct contains a number of fields that may be queried for
PCI information:

* `pcidb.PCIDB.Classes` is a map, keyed by the PCI class ID (a hex-encoded
  string) of pointers to `pcidb.Class` structs, one for each class of PCI
  device known to `pcidb`
* `pcidb.PCIDB.Vendors` is a map, keyed by the PCI vendor ID (a hex-encoded
  string) of pointers to `pcidb.Vendor` structs, one for each PCI vendor
  known to `pcidb`
* `pcidb.PCIDB.Products` is a map, keyed by the PCI product ID* (a hex-encoded
  string) of pointers to `pcidb.Product` structs, one for each PCI product
  known to `pcidb`

**NOTE**: PCI products are often referred to by their "device ID". We use
the term "product ID" in `pcidb` because it more accurately reflects what the
identifier is for: a specific product line produced by the vendor.

### PCI device classes

Let's take a look at the PCI device class information and how to query the PCI
database for class, subclass, and programming interface information.

Each `pcidb.Class` struct contains the following fields:

* `pcidb.Class.ID` is the hex-encoded string identifier for the device
  class
* `pcidb.Class.Name` is the common name/description of the class
* `pcidb.Class.Subclasses` is an array of pointers to
  `pcidb.Subclass` structs, one for each subclass in the device class

Each `pcidb.Subclass` struct contains the following fields:

* `pcidb.Subclass.ID` is the hex-encoded string identifier for the device
  subclass
* `pcidb.Subclass.Name` is the common name/description of the subclass
* `pcidb.Subclass.ProgrammingInterfaces` is an array of pointers to
  `pcidb.ProgrammingInterface` structs, one for each programming interface
   for the device subclass

Each `pcidb.ProgrammingInterface` struct contains the following fields:

* `pcidb.ProgrammingInterface.ID` is the hex-encoded string identifier for
  the programming interface
* `pcidb.ProgrammingInterface.Name` is the common name/description for the
  programming interface

```go
package main

import (
    "fmt"

    "github.com/jaypipes/pcidb"
)

func main() {
    pci, err := pcidb.New()
    if err != nil {
        fmt.Printf("Error getting PCI info: %v", err)
    }

    for _, devClass := range pci.Classes {
        fmt.Printf(" Device class: %v ('%v')\n", devClass.Name, devClass.ID)
        for _, devSubclass := range devClass.Subclasses {
            fmt.Printf("    Device subclass: %v ('%v')\n", devSubclass.Name, devSubclass.ID)
            for _, progIface := range devSubclass.ProgrammingInterfaces {
                fmt.Printf("        Programming interface: %v ('%v')\n", progIface.Name, progIface.ID)
            }
        }
    }
}
```

Example output from my personal workstation, snipped for brevity:

```
...
 Device class: Serial bus controller ('0c')
    Device subclass: FireWire (IEEE 1394) ('00')
        Programming interface: Generic ('00')
        Programming interface: OHCI ('10')
    Device subclass: ACCESS Bus ('01')
    Device subclass: SSA ('02')
    Device subclass: USB controller ('03')
        Programming interface: UHCI ('00')
        Programming interface: OHCI ('10')
        Programming interface: EHCI ('20')
        Programming interface: XHCI ('30')
        Programming interface: Unspecified ('80')
        Programming interface: USB Device ('fe')
    Device subclass: Fibre Channel ('04')
    Device subclass: SMBus ('05')
    Device subclass: InfiniBand ('06')
    Device subclass: IPMI SMIC interface ('07')
    Device subclass: SERCOS interface ('08')
    Device subclass: CANBUS ('09')
...
```

### PCI vendors and products

Let's take a look at the PCI vendor information and how to query the PCI
database for vendor information and the products a vendor supplies.

Each `pcidb.Vendor` struct contains the following fields:

* `pcidb.Vendor.ID` is the hex-encoded string identifier for the vendor
* `pcidb.Vendor.Name` is the common name/description of the vendor
* `pcidb.Vendor.Products` is an array of pointers to `pcidb.Product`
  structs, one for each product supplied by the vendor

Each `pcidb.Product` struct contains the following fields:

* `pcidb.Product.VendorID` is the hex-encoded string identifier for the
  product's vendor
* `pcidb.Product.ID` is the hex-encoded string identifier for the product
* `pcidb.Product.Name` is the common name/description of the subclass
* `pcidb.Product.Subsystems` is an array of pointers to
  `pcidb.Product` structs, one for each "subsystem" (sometimes called
  "sub-device" in PCI literature) for the product

**NOTE**: A subsystem product may have a different vendor than its "parent" PCI
product. This is sometimes referred to as the "sub-vendor".

Here's some example code that demonstrates listing the PCI vendors with the
most known products:

```go
package main

import (
    "fmt"
    "slices"

    "github.com/jaypipes/pcidb"
)

func main() {
    pci, err := pcidb.New()
    if err != nil {
        fmt.Printf("Error getting PCI info: %v", err)
    }

    vendors := make([]*pcidb.Vendor, len(pci.Vendors))
    x := 0
    for _, vendor := range pci.Vendors {
        vendors[x] = vendor
        x++
    }

    slices.SortFunc(vendors, func(a, b *pcidb.Vendor) int {
        return cmp.Compare(len(a.Products), len(b.Products))
    })
    slices.Reverse(vendors)

    fmt.Println("Top 5 vendors by product")
    fmt.Println("====================================================")
    for _, vendor := range vendors[0:5] {
        fmt.Printf("%v ('%v') has %d products\n", vendor.Name, vendor.ID, len(vendor.Products))
    }
}
```

which yields (on my local workstation as of August 23rd, 2025):

```
Top 5 vendors by product
====================================================
Intel Corporation ('8086') has 4461 products
NVIDIA Corporation ('10de') has 1853 products
Advanced Micro Devices, Inc. [AMD/ATI] ('1002') has 1115 products
Chelsio Communications Inc ('1425') has 669 products
National Instruments ('1093') has 609 products
```

The following is an example of querying the PCI product and subsystem
information to find the products which have the most number of subsystems that
have a different vendor than the top-level product. In other words, the two
products which have been re-sold or re-manufactured with the most number of
different companies.

```go
package main

import (
    "fmt"
    "sort"

    "github.com/jaypipes/pcidb"
)

type ByCountSeparateSubvendors []*pcidb.Product

func (v ByCountSeparateSubvendors) Len() int {
    return len(v)
}

func (v ByCountSeparateSubvendors) Swap(i, j int) {
    v[i], v[j] = v[j], v[i]
}

func (v ByCountSeparateSubvendors) Less(i, j int) bool {
    iVendor := v[i].VendorID
    iSetSubvendors := make(map[string]bool, 0)
    iNumDiffSubvendors := 0
    jVendor := v[j].VendorID
    jSetSubvendors := make(map[string]bool, 0)
    jNumDiffSubvendors := 0

    for _, sub := range v[i].Subsystems {
        if sub.VendorID != iVendor {
            iSetSubvendors[sub.VendorID] = true
        }
    }
    iNumDiffSubvendors = len(iSetSubvendors)

    for _, sub := range v[j].Subsystems {
        if sub.VendorID != jVendor {
            jSetSubvendors[sub.VendorID] = true
        }
    }
    jNumDiffSubvendors = len(jSetSubvendors)

    return iNumDiffSubvendors > jNumDiffSubvendors
}

func main() {
    pci, err := pcidb.New()
    if err != nil {
        fmt.Printf("Error getting PCI info: %v", err)
    }

    products := make([]*pcidb.Product, len(pci.Products))
    x := 0
    for _, product := range pci.Products {
        products[x] = product
        x++
    }

    sort.Sort(ByCountSeparateSubvendors(products))

    fmt.Println("Top 2 products by # different subvendors")
    fmt.Println("====================================================")
    for _, product := range products[0:2] {
        vendorID := product.VendorID
        vendor := pci.Vendors[vendorID]
        setSubvendors := make(map[string]bool, 0)

        for _, sub := range product.Subsystems {
            if sub.VendorID != vendorID {
                setSubvendors[sub.VendorID] = true
            }
        }
        fmt.Printf("%v ('%v') from %v\n", product.Name, product.ID, vendor.Name)
        fmt.Printf(" -> %d subsystems under the following different vendors:\n", len(setSubvendors))
        for subvendorID, _ := range setSubvendors {
            subvendor, exists := pci.Vendors[subvendorID]
            subvendorName := "Unknown subvendor"
            if exists {
                subvendorName = subvendor.Name
            }
            fmt.Printf("      - %v ('%v')\n", subvendorName, subvendorID)
        }
    }
}
```

which yields (on my local workstation as of August 23rd, 2025):

```
Top 2 products by # different subvendors
====================================================
RTL-8100/8101L/8139 PCI Fast Ethernet Adapter ('8139') from Realtek Semiconductor Co., Ltd.
 -> 34 subsystems under the following different vendors:
      - ASUSTeK Computer Inc. ('1043')
      - Matsushita Electric Industrial Co., Ltd. ('10f7')
      - Compex ('11f6')
      - Allied Telesis ('1259')
      - Samsung Electronics Co Ltd ('144d')
      - Micro-Star International Co., Ltd. [MSI] ('1462')
      - Ruby Tech Corp. ('146c')
      - ZyXEL Communications Corporation ('187e')
      - TTTech Computertechnik AG (Wrong ID) ('0357')
      - Accton Technology Corporation ('1113')
      - Billionton Systems Inc ('14cb')
      - Belkin ('1799')
      - Hangzhou Silan Microelectronics Co., Ltd. ('1904')
      - AOPEN Inc. ('a0a0')
      - Acer Incorporated [ALI] ('1025')
      - Surecom Technology ('10bd')
      - D-Link System Inc ('1186')
      - Hewlett-Packard Company ('103c')
      - Mitac ('1071')
      - Netgear ('1385')
      - Edimax Computer Co. ('1432')
      - Packard Bell B.V. ('1631')
      - Gigabyte Technology Co., Ltd ('1458')
      - KTI ('8e2e')
      - CIS Technology Inc ('1436')
      - Red Hat, Inc. ('1af4')
      - Kingston Technology Company, Inc. ('2646')
      - KYE Systems Corporation ('1489')
      - Ambicom Inc ('1395')
      - Unex Technology Corp. ('1429')
      - OVISLINK Corp. ('149c')
      - Biostar Microtech Int'l Corp ('1565')
      - EPoX Computer Co., Ltd. ('1695')
      - U.S. Robotics ('16ec')
Bt878 Video Capture ('036e') from Brooktree Corporation
 -> 32 subsystems under the following different vendors:
      - Hauppauge computer works Inc. ('0070')
      - Askey Computer Corp. ('144f')
      - Avermedia Technologies Inc ('1461')
      - iTuner ('aa00')
      - iTuner ('aa0f')
      - Pinnacle Systems Inc. ('11bd')
      - Euresys S.A. ('1805')
      - Twinhan Technology Co. Ltd ('1822')
      - iTuner ('aa05')
      - iTuner ('aa08')
      - Nebula Electronics Ltd. ('0071')
      - Chaintech Computer Co. Ltd ('270f')
      - Conexant Systems, Inc. ('14f1')
      - iTuner ('aa01')
      - iTuner ('aa03')
      - iTuner ('aa0b')
      - iTuner ('aa0d')
      - Microtune, Inc. ('1851')
      - iTuner ('aa02')
      - iTuner ('aa06')
      - iTuner ('aa09')
      - Anritsu Corp. ('1852')
      - iTuner ('aa04')
      - iTuner ('aa07')
      - iTuner ('aa0c')
      - Pinnacle Systems, Inc. (Wrong ID) ('bd11')
      - Unknown subvendor ('0000')
      - Rockwell International ('127a')
      - DViCO Corporation ('18ac')
      - iTuner ('aa0e')
      - LeadTek Research Inc. ('107d')
      - iTuner ('aa0a')
```

## Discovery

`pcidb` tries its best to automatically discover a `pci.ids` database file on
the local host.

`pcidb`'s default behaviour is to first search for `pci.ids` DB files on the
local host system in well-known filesystem paths (Linux and MacOS):

* `/usr/share/hwdata/pci.ids`
* `/usr/share/misc/pci.ids.gz`
* `/usr/share/hwdata/pci.ids`
* `/usr/share/misc/pci.ids.gz`

> **NOTE**: Windows does not have a `pci.ids` database file installed by
> default.

You can influence this discovery behaviour with the functions discussed in the
following sections.

### Overriding the location of the `pci.ids` database file

If you have a copy of a `pci.ids` database file in a non-standard location or
are working in an environment like Windows that does not have a `pci.ids`
database file installed by default and do not want `pcidb` to fetch an
up-to-date `pci.ids` database file over the network, you can tell `pcidb`
exactly where to find the `pci.ids` database using the `pcidb.WithPath()`
function, like so:

```go
pci := pcidb.New(pcidb.WithPath("/path/to/pci.ids.gz"))
```

### Overriding the root mountpoint `pcidb` uses

The default root mountpoint that `pcidb` uses when looking for information
about the host system is `/`. So, for example, when looking up known `pci.ids`
database files on Linux, `pcidb` will attempt to discover a `pci.ids` database
file at `/usr/share/misc/pci.ids`. If you are calling `pcidb` from a system
that has an alternate root mountpoint, you can either set the `PCIDB_CHROOT`
environment variable to that alternate path, or call the `pcidb.New()` function
with the `pcidb.WithChroot()` modifier.

For example, if you are executing from within an application container that has
bind-mounted the root host filesystem to the mount point `/host`, you would set
`PCIDB_CHROOT` to `/host` so that pcidb can find files like
`/usr/share/misc/pci.ids` at `/host/usr/share/misc/pci.ids`.

Alternately, you can use the `pcidb.WithChroot()` function like so:

```go
pci := pcidb.New(pcidb.WithChroot("/host"))
```

### Fetching `pci.ids` database file over the network

If `pcidb` cannot find a `pci.ids` DB file on the local host system, you can
configure `pcidb` to fetch a current `pci.ids` DB file from the network. You
can enable this network-fetching behaviour with the
`pcidb.WithEnableNetworkFetch()` function or set the
`PCIDB_ENABLE_NETWORK_FETCH` environs variable to a non-0 value.

## Developers

Contributions to `pcidb` are welcomed! Fork the repo on GitHub and submit a pull
request with your proposed changes. Or, feel free to log an issue for a feature
request or bug report.

### Running tests

You can run unit tests easily using the `make test` command, like so:

```
[jaypipes@uberbox pcidb]$ make test
go test github.com/jaypipes/pcidb
ok      github.com/jaypipes/pcidb    0.045s
```
