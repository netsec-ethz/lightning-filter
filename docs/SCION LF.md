# LightningFilter over SCION

LightningFilter has been developed and optimized to run in a SCION network.
In the SCION environment, an AS-based DRKey system is provided that seamlessly can be used by LightningFilter.
Furthermore, the SCION Packet Authenticator Option (SPAO), which is a SCION header extension, allows to add authentication data to a SCION packet used by LightningFilter.

This chapter presents in more detail, how the SCION DRKey infrastructure is used by LightningFilter and how LightningFilter applies the SPAO.

## SCION DRKey Infrastructure

The SCION DRKey infrastructure documentation can be found [here](https://scion.docs.anapaya.net/en/latest/cryptography/drkey.html).

The LightingFilter implementation keeps a table of Level 1 DRKeys, which are defined in the configuration with the peer AS's IA number and the DRKey protocol identifier.
The Level 1 DRKeys are provided by the SCION DRKey infrastructure.
LF updates the table in regular intervals ensuring that it always contains valid keys (also considering the grace period).

The per-packet MAC is computed with the host-host DRKey that is directly derived in one step from the AS-AS key:

$K_{A:HA->B:HB} = PRF_{K_{A->B}}(HA||HB)$

> Note that this derivation deviates from the DRKey documentation and is likely to change in the future.

## SCION Packet Authenticator Option (SPAO)

The SPAO header documentation can be found [here](https://scion.docs.anapaya.net/en/latest/protocols/authenticator-option.html).

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

> The timestamp in the SPAO header provides a relative offset to the timestamp in the SCION path in nanoseconds. Therefore, the SPAO header is not defined for packets which use the "Empty" path type. This is the case for AS-local traffic. Hence, LightningFilter can currently not be used for AS-local traffic. Nevertheless, the issue is discussed online [here](https://github.com/scionproto/scion/issues/4062).