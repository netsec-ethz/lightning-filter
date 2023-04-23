# Functionalities

## Authentication

Traffic authentication is based on the DRKey scheme defined for SCION, which has also been described for PISKES.

There are mainly two functional requirements for LightningFilter that determine the DRKey scheme.
1. On the receiver side, the LightningFilter must be able to derive any required communication key.
2. On the sender side, the end host should be able to create LightningFilter packets for a specific destination. However, the end host should not be able to create LightningFilter packets for any other communication.

Given the requirements, the derivation scheme consists of at least 3 Levels; AS Secret, AS-AS key, and host-host key.
Requirement 1. is achieved by using the AS secret to derive all possible keys on the receiver side. Requirement 2 is fulfilled by providing host-host keys to the end host on the sender side.

## Rate Limiting

1. On the receiver side, the LightningFilter must enforce rate limits that are defined per AS and DRKey protocol.

## Duplicate Detection

1. On the receiver side, the LightningFilter must detect duplicate packets.
