# Metrics

The DPDK telemetry API provides information and statistics of a running DPDK instance.
Also, statistics collected by LightningFilter can be accessed through this interface.

## Monitoring Stack

There are various ways to collect, aggregate, and monitor the metrics provided through the DPDK telemetry interface. A possible setup is presented in [monitoring/Monitoring.md](monitoring/Monitoring.md)).

## Client Script

A simple way to interact with the API directly, is with the help of the provided client script.

```
sudo ./usertools/lf-telemetry.py
```

When the DPDK application uses a file prefix, the file prefix has to be passed via the -f flag:

```
sudo ./usertools/lf-telemetry.py -f "file_prefix"
```

After starting the client script, various metrics can be requested. The responses are then provided in JSON format.
The client script provides a list of all available metrics and a help text for each.

## Available Metrics

The following sections describe some of the metrics offered by LightningFilter.

### Version

Path:
`/lf/version`

Description:
Version information of the running application, including git hash, and LightningFilter options.


Format (experimental):
```
{
    "major": major version number,
    "version": version number (string),
    "git": git version (string),
    "worker": worker type (string),
    "drkey_fetcher": drkey fetcher type (string),
    "cbc_mac": CBC MAC engine (string),
    "log_dp_level": compiled data plane log level
}
```

### EAL Parameters

Path:
`/eal/params`

Description:
List of provided EAL parameters.

### Application PArameters
Path:
`/eal/app_params`

Description:
List of provided application parameters.

## Traffic Metrics

### Worker
Path:
`/lf/worker/stats`

Parameter:
None for aggregated statistics or `<worker_id>` for a specific worker's statistics.

Description:
General traffic metrics collected by workers.

Format (experimental):
```
{
"rx_pkts": receive packets,
"rx_bytes": receive bytes,
"tx_pkts": transmitted packets,
"tx_bytes": transmitted bytes,
"drop_pkts": dropped packets,
"drop_bytes": dropped bytes,
"besteffort_pkt": best-effort packets,
"besteffort_bytes": best-effort bytes,
"error": # packets caused an error,
"no_key": # packets no key found,
"invalid_mac": # packets with invalid mac,
"outdated_timestamp": # packets with outdated timestamp,
"duplicate": # packets detected as duplicate,
"ratelimit_as": # packets exceeded AS rate limit,
"ratelimit_system": # packets exceeded system-wide rate limit,
"valid": # packets passed all checks
}
```

### Port

Path:
`/ethdev/xstats,<port_id>`

Description:
Extended statistics for an ethdev port.

## Key Manager Metrics

### DRKey Fetching

Path:
`/lf/keymanager/stats`

### Dictionary

Path:
`/lf/keymanager/dict`


## General

### Commands

Path:
`/`

Description:
List all commands.

### Help

Path:
`/help,<command>`

Description:
Help text for a command.
