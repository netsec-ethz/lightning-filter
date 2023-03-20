# Troubleshooting

## Fail to Start
### Unable to allocate memory
Ensure that enough memory is given to the huge pages.

```
echo '4096' | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

## Performance

Ensure that unnecessary logs on the data path are not compiled. This can be adjusted by setting LF_LOG_DP_LEVEL to 0 or any other reasonable value (e.g., LF_LOG_ERR).

## Lost Packets

Ensure that packets are not larger than the MTU. LightningFilter adds information to outgoing packets without checking the MTU. Therefore, the MTU for packets sent to the LightningFilter has to be set appropriately. Note that this issue does not occur when the packets are small, e.g., when sending ping requests, but will occur when the packets are large, e.g., when testing bandwidth with iperf.
