# Introduction

**go-libzfs** currently implements basic manipulation of ZFS pools and data sets. Plan is to add more in further development, improve documentation with more examples, and add more tests. _go-libzfs_ use libzfs C library and does not wrap OpenZFS CLI tools. Goal is to let easy using and manipulating OpenZFS form with in go, and tries to map libzfs C library in to go style package respecting golang common practice.

## Note
This golang package is only used and tested on Linux.

- Version tagged as v0.1 is latest used and compatible with ZFS On Linux version 0.6.5.x
- Version tagged as v0.2 is latest used and compatible with ZFS On Linux version 0.7.x

[![GoDoc](https://godoc.org/github.com/bicomsystems/go-libzfs?status.svg)](https://godoc.org/github.com/bicomsystems/go-libzfs)

## Main features

- Creating, destroying, importing and exporting pools.
- Reading and modifying pool properties.
- Creating, destroying and renaming of filesystem datasets and volumes.
- Creating, destroying and rollback of snapshots.
- Cloning datasets and volumes.
- Reading and modifying dataset and volume properties.
- Send and receive snapshot streams


## Requirements:

- OpenZFS on Linux and libzfs with development headers installed.
- Developed using go1.9

## Installing

```sh
go get github.com/bicomsystems/go-libzfs
```

## Testing

```sh
# On command line shell run
cd $GOPATH/src/github.com/bicomsystems/go-libzfs
go test
```

## Usage example

```go
// Create map to represent ZFS dataset properties. This is equivalent to
// list of properties you can get from ZFS CLI tool, and some more
// internally used by libzfs.
props := make(map[ZFSProp]Property)

// I choose to create (block) volume 1GiB in size. Size is just ZFS dataset
// property and this is done as map of strings. So, You have to either
// specify size as base 10 number in string, or use strconv package or
// similar to convert in to string (base 10) from numeric type.
strSize := "1073741824"

props[DatasetPropVolsize] = Property{Value: strSize}
// In addition I explicitly choose some more properties to be set.
props[DatasetPropVolblocksize] = Property{Value: "4096"}
props[DatasetPropReservation] = Property{Value: strSize}

// Lets create desired volume
d, err := DatasetCreate("TESTPOOL/VOLUME1", DatasetTypeVolume, props)
if err != nil {
	println(err.Error())
	return
}
// Dataset have to be closed for memory cleanup
defer d.Close()

println("Created zfs volume TESTPOOL/VOLUME1")
```

## Special thanks to

- [Bicom Systems](http://www.bicomsystems.com) for supporting this little project and that way making it possible.
- [OpenZFS](http://open-zfs.org) as the main ZFS software collective.