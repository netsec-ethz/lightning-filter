# LightningFilter over SCION

LightningFilter has been developed and optimized to run in a SCION network.
In the SCION environment, an AS-based DRKey system is provided that can seamlessly be used by LightningFilter.
Furthermore, the SCION Packet Authenticator Option (SPAO) is a SCION header extension that adds authenticators to a SCION packet and is used by LightningFilter.

This chapter presents, in more detail, how LightningFilter uses the SCION DRKey infrastructure and how it applies SPAO.

## SCION DRKey Infrastructure

The SCION DRKey infrastructure documentation can be found [here](https://docs.scion.org/en/latest/cryptography/drkey.html).

LightingFilter keeps a table of Level 1 DRKeys for communicating with peers defined in the configuration.
The SCION DRKey infrastructure provides the Level 1 DRKeys to LightningFilter.
LF regularly updates the DRKey table, ensuring it always contains valid keys.

The per-packet MAC is computed with the host-host DRKey that is directly derived in one step from the AS-AS key:

$K_{A:HA->B:HB} = PRF_{K_{A->B}}(HA||HB)$

> Note that this derivation deviates from the DRKey documentation and is likely to change in the future.

## SCION Packet Authenticator Option (SPAO)

The SPAO header documentation can be found [here](https://docs.scion.org/en/latest/protocols/authenticator-option.html).

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                |   OptType=2   |  OptDataLen   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Security Parameter Index                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Algorithm  |      RSV      |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                     Timestamp/Sequence Number                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Authenticator ...                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

LightningFilter utilizes the SPAO header as documented with the SHA1-AES-CBS algorithm and DRKey format of the security parameter index.
The timestamp in the SPAO header provides a relative offset to the start of the DRKey epoch in nanoseconds. The corresponding DRKey epoch selection is described [here](https://docs.scion.org/en/latest/protocols/authenticator-option.html#absolute-time-and-drkey-selection).