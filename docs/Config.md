# Config
The LightningFilter configuration file is written in JSON format. In the following we describe the possible options.

**isd_as** (string)  
Local ISD-AS number in the SCION IA format (e.g., "1-ff00:0:110").

**drkey_protocol** (number)  
The DRKey protocol number used for all outbound traffic.

**ratelimit** (Rate Limit)  
The rate limit for all forwarded incoming traffic.

**auth_peers** (contains field *ratelimit*: Rate Limit)  
The rate limit for forwarded incoming traffic from authenticated peers for which no peer-specific rate limit is provided (see *peers* for more details).

**best_effort** (contains field *ratelimit*: Rate Limit)  
The rate limit for incoming best-effort traffic.

**peers** (array)  
List of remote peers.

> *Key Manager:* For each peer in the list, The key manager adds inbound and outbound keys to the table. In case a key does not exist in the table for a packet, the packet is dropped.

> *Rate Limiter:* For each peers in this list with a rate limit defined, the rate limiter module adds inbound rate limits to the table. In case a rate limit does not exist in the table for a packet, the *auth_peers* rate limit is applied.

**drkey_service_addr** (string)  
UDP address of SCION DRKey service, which is usually the control service.

**inbound** (Packet Modifier)  
Packet modifier for inbound traffic when being forwarded. E.g., the address of the next hop, such as the gateway, can be defined here.

**outbound** (Packet Modifier)  
Packet modifier for outbound traffic when being forwarded. E.g., the address of the local router or switch can be defined here.

**port** (number)  
*Only IP LF:* UDP destination port of encapsulated LF packets.

**ip_public** (string)  
*Only IP LF:* The public IP address of the LightingFilter in case the LightningFilter is behind a NAT and the NAT alters destination or source addresses in the packet for inbound or outbound packets, respectively.

## Packet Modifier
For a packet modifier, the following fields are available.

**ether** (string)  
Destination Ethernet address.
If an address is provided, the Ethernet destination address is set to that address.
If the string `"src_addr"` is provided, the destination and source addresses are switched.
The destination Ethernet address is not set if this field is not provided.

**ip** (string)  
Destination IPv4 address. The destination IP address is not set if this field is not provided.

**ipv6** (string, not fully supported)  
Destination IPv6 address. The destination IP address is not set if this field is not provided.

## Peer
For a peer, the following fields are available.

**isd_as** (string)  
The ISD-AS number of the peer in the SCION IA format (e.g., "1-ff00:0:110"). This field is required.

**drkey_protocol** (number)  
The DRKey protocol number serves as an additional identifier for the peer. If not defined, a default DRKey protocol number is used.

**ratelimit** (Rate Limit)  
(Optional) The rate limit for inbound packets sent from this peer.

## Rate Limit
For rate limits, the following fields are available.

**byte_rate** (number)  
The rate limit in bytes per second.

**byte_burst** (number)  
The maximal number of bytes accepted at once. Note that the granularity of the rate limiter is in nanoseconds.

**packet_rate** (number)  
The rate limit in packets per second.

**packet_burst** (number)  
The maximal number of packets accepted at once. Note that the granularity of the rate limiter is in nanoseconds.