# Features

## Checksum Offloading

IP, UDP, and TCP checksum offloading is enabled by default.
It can be disabled by setting the `LF_OFFLOAD_CKSUM` compile flag accordingly:

```
cmake ../ -D LF_OFFLOAD_CKSUM=OFF
```

## Jumbo Frames

The processing of packets larger than 1500 bytes, i.e., jumbo frames, is supported but has to be enabled with the `LF_JUMBO_FRAME` compile-time flag.

```
cmake ../ -D LF_JUMBO_FRAME=ON
```

Enabling jumbo frames can cause higher memory consumption and lower performance, especially when processing small packets. Hence, for optimal performance, enable it only when needed.

Note that the port's MTU must also be configured to allow large packets with the `--mtu` (LF application) parameter.
E.g.:

```
lf_exec [DPDK EAL parameters] -- [LF parameters] --mtu 9000
```
