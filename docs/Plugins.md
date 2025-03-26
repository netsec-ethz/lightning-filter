# Plugins

Plugins are modules that can be enabled to extend the packet processing pipeline.
E.g., a plugin could filter traffic before it is processed by a worker, i.e., core modules. Intra-AS packets could be forwarded directly without further processing, or rate limited could be applied for certain packets.

In LF, to enable a plugin, add its name to the colon-separated list of the CMake variable `LF_PLUGINS`. E.g.:

```
cmake -D LF_PLUGINS=\"dst_ratelimiter:wg_ratelimiter\"
```

## Host Ratelimiter (name: dst_ratelimiter)

The host ratelimiter plugin allows to define rate limits for destination addresses.
These rate limits are applied after the packet has successfully passed all core checks and would be forwarded (note that also best-effort traffic is considered here).

## WG Ratelimiter (name: wg_ratelimiter)

With the WireGuard (WG) ratelimiter plugin, additional rate limits for WG handshake packets and WG data packets can be enforced.
WG packets are identified by the UDP destination port, which can be configured.
