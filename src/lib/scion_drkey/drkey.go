// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2021 ETH Zurich

package main

import (
	"C"
	"unsafe"
)

//export GetHOSTASKey
func GetHOSTASKey(sciondAddr *C.char, fastIA, slowIA, fastAddr uint64, drkeyProtocol uint16, valTime int64,
	validityNotBefore, validityNotAfter *int64, keyPtr unsafe.Pointer) int {

	return -1
}

//export GetHOSTHOSTKey
func GetHOSTHOSTKey(sciondAddr *C.char, fastIA, slowIA, fastAddr, slowAddr uint64, drkeyProtocol uint16, valTime int64,
	validityNotBefore, validityNotAfter *int64, keyPtr unsafe.Pointer) int {

	return -1
}

func main() {}
