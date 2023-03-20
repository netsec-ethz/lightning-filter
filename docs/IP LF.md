# LightningFilter over IP

## Encapsulation

For outgoing packets, LightningFilter encapsulates the IP packet's payload into a UDP/LF header.

ETH/IP/Payload => ETH/IP/UDP/LF/Payload

The UDP header uses a specified port to identify LightningFilter encapsulated packets. Usually port 49149 is used.
The LF header contains the payloads protocol ID, i.e., the protocol ID in the IP header previous to the encapsulation.

## Header Format

The LF header has the following format:
```
 0                   1                   2                   3  
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                         Source ISD-AS                         +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          DRKey Proto          |    Reserved   | Payload Proto |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                           Timestamp                           +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                          Payload Hash                         |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                              MAC                              +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Source ISD-AS**  
64-bit ISD-AS number of the source in the SCION format (16-bit ISD, 48-bit AS).

**DRKey Proto**  
16-bit DRKey-protocol identifier.

**Reserved**  
8-bit of reserved value. MUST be zero.

**Payload Proto**  
8-bit protocol number of the payload following the LF header. The protocol number corresponds to the protocol number in the IP header before the packet has been encapsulated.

**Timestamp**  
64-bit unsigned Unix timestamp in nanoseconds.
The timestamp must be unique for packets from the same source AS.
> The timestamp format might change in the future.

**Payload Hash**
20-byte SHA-1 hash of the payload.

**MAC**
16-byte CBC-MAC of the authenticated data with the DRKey derived from the source ISD-AS and source address.

## Authenticated Data

For the MAC calculation, the "DRKey Protocol" field is overwritten with the length of the payload (in network byte order). The packet length can be derived by the lengths provided in the IP or UDP header. The MAC is then calculated over all fields after the "Source AS Number" field up to the "MAC" field.

## Wireshark

It can be helpful to analyze packets with Wireshark when troubleshooting LightningFilter traffic.
Therefore, install the dissector Lua plugin provided in the `usertools` folder by copying the file to one of the Wireshark's plugin folders.
How to find the Wireshark's plugin folders is documented [here](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).