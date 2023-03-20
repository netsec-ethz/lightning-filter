# Plugins

Plugins are modules, which can be activated to add additional functionalities.
E.g., a plugin could filter traffic before it is processed by a worker, i.e., core modules. Intra-AS packets could directly be forwarded without further processing, or packets could be dropped with respect to a deny list.

## Host Ratelimiter
The host ratelimiter plugin allows to define rate limits for destination addresses.
These rate limits are applied after the packet has successfully passed all core checks and would be forwarded (note that also best-effort traffic is considered here).

## WG Ratelimiter
With the WireGuard (WG) ratelimiter plugin, additional rate limits for WG handshake packets and WG data packets can be enforced.
WG packets are identified by the UDP destination port, which can be configured.