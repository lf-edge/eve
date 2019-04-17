package main

// #include <linux/random.h>
//
// int rndaddentropy = RNDADDENTROPY;
//
import "C"

import (
	"encoding/binary"
	"os"
)

// No standard RNG on arm64

var urandom *os.File

func initRand() bool {
	file, err := os.Open("/dev/urandom")
	urandom = file
	return (err == nil)
}

func rand() (uint64, error) {
	var rand uint64
	err := binary.Read(urandom, binary.LittleEndian, &rand)
	return rand, err
}
