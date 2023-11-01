# Golang uevent bindings

This golang library implements uevent bindings for reading and decoding Linux kernel udev events.

## Usage

```
package main

import (
	"fmt"
	"log"

	"github.com/s-urbaniak/uevent"
)

func main() {
	r, err := uevent.NewReader()
	if err != nil {
		log.Fatal(err)
	}

	dec := uevent.NewDecoder(r)

	for {
		evt, err := dec.Decode()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(evt)
	}
}
```

## Prerequisites

Linux
