# DRKey

## Test
build:
```
./build.sh
make -C test
```

The SCION DRKey fetcher test fetches DRKeys from the SCION control service (CS).
The test expects following parameters:
`<CS address> <ISD-AS slow side> <ISD-AS fast side> <DRKey protocol number>`

### SCION Test Network
The SCION DRKey fetcher can be tested within the SCION Test Network (see `lf/test/testnet_scion`).

```
test/build/sdrkey_test "127.0.0.12:31000" 0x0001ff0000000111 0x0001ff0000000110 3
test/build/sdrkey_test "10.248.7.1:31008" 0x0001ff0000000110 0x0001ff0000000111 3
test/build/sdrkey_test "10.248.8.1:31014" 0x0001ff0000000112 0x0001ff0000000111 3
```

As the LightningFilter is located in the near namespaces, tests should also be conducted from there.
```
sudo ip netns exec near-0 test/build/drkey_test "10.248.7.1:31008" 0x0001ff0000000110 0x0001ff0000000111 3
sudo ip netns exec near-1 test/build/drkey_test "10.248.8.1:31014" 0x0001ff0000000112 0x0001ff0000000111 3
```