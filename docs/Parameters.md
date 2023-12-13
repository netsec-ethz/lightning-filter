# Parameters

```
lf_exec [DPDK EAL parameters] -- [LF parameters]
```

## LF Parameters

The LightningFilter help option prints the available parameters:

```
-h, --help
```

## DPDK EAL Parameters

DPDK documentation: 
http://doc.dpdk.org/guides-23.11/linux_gsg/linux_eal_parameters.html

### Lcore-relation option

The following parameters define the mapping between logical and physical cores.

```
-l <core list>
```

```
--lcores <core map>
```

### Device-relation options

Add a PCI device to the list of allowed devices. Multiple -a options are allowed.

```
-a, --allow <[domain:]bus:devid.func>
```

Add a PCI device to the list of blocked devices. Multiple -b options are allowed.

```
-b, --block <[domain:]bus:devid.func>
```

The allow list option and the block list option cannot be used together.

### Debugging options

Specify the log level for a specific component.

```
--log-level <type:val>
```

E.g.:

```
--log-level lf:debug
```
