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

	/*
		meta := drkey.Lvl1Meta{
			ProtoId:  drkey.Protocol(drkeyProtocol),
			Validity: time.Unix(valTime/1000, 0).UTC(),
			SrcIA:    addr.IA(fastIA),
			DstIA:    addr.IA(slowIA),
		}

		ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelF()

		// Dial
		conn, err := grpc.DialContext(ctx, C.GoString(sciondAddr), grpc.WithInsecure())
		if err != nil {
			fmt.Println("DialContext failed")
			return -1
		}

		defer conn.Close()
		client := cppb.NewDRKeyIntraServiceClient(conn)


			protoReq, err := drkeyctrl.IntraLvl1ToProtoRequest(meta)
			if err != nil {
				fmt.Println("IntraLvl1ToProtoRequest failed")
				return -1
			}

			rep, err := client.IntraLvl1(ctx, protoReq)
			if err != nil {
				fmt.Println("IntraLvl1 failed")
				return -1
			}

			key, err := drkeyctrl.GetASASKeyFromReply(meta, rep)
			if err != nil {
				fmt.Println("GetASASKeyFromReply failed")
				return -1
			}
	*/

	*validityNotBefore = 0 * 1000
	*validityNotAfter = 1800000000 * 1000
	key := new(drkey.Key)[:]
	copy((*[16]byte)(keyPtr)[:], key[:])

	return 0
}

func main() {}
