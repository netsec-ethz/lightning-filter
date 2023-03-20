# Parameters

```
lf_exec [DPDK EAL parameters] -- [LF parameters]
```

## LF Parameters
The LightningFilter parameter list can be printed with the help option:
```
-h, --help
```

## DPDK EAL Parameters
DPDK documentation: 
https://doc.dpdk.org/guides-21.11/linux_gsg/linux_eal_parameters.html

### Lcore-relation option
The following to parameters define the mapping between logical and physical cores.

```
-l <core list>
```

```
--lcores <core map>
```

### Device-relation options

```
-a, --allow <[domain:]bus:devid.func>
```
Add a PCI device in to the list of devices to probe.

```
-b, --block <[domain:]bus:devid.func>
```
Skip probing a PCI device to prevent EAL from using it. Multiple -b options are allowed.

The allow list option and the block list option cannot be used together.

### Debugging options

```
--log-level <type:val>
```
Specify log level for a specific component. For example:

```
--log-level lf:debug
```