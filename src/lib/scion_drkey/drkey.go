// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2021 ETH Zurich

package main

import (
	"C"
	"unsafe"

	"github.com/scionproto/scion/pkg/drkey"
)

//export GetASASKey
func GetASASKey(sciondAddr *C.char, fastIA, slowIA uint64, drkeyProtocol uint16, valTime int64,
	validityNotBefore, validityNotAfter *int64, keyPtr unsafe.Pointer) int {

	// This just creates a 0...0 key for testing
	*validityNotBefore = 0 * 1000
	*validityNotAfter = 1800000000 * 1000
	key := new(drkey.Key)[:]
	copy((*[16]byte)(keyPtr)[:], key[:])

	return 0
}

func main() {}
