# Control Traffic

LightningFilter offers support to handle control traffic (ct) packets, such as ARP requests. Therefore, it utilizes the system's network stack to perform the processing with the help of virtual devices.

LightningFilter creates a virtual device with the same MAC address for each port.
Control traffic packets a port receives are then filtered and forwarded to the port's corresponding virtual device.
The received packet is processed on the virtual device, and an appropriate response is created, which is then sent out over the port.
With this approach, it is not necessary to implement ARP protocol in LightingFilter, keeping the source code to a minimum.

### Filtering

The filtering of control traffic packets is offloaded to the NIC with the help of DPDK's flow API.
The NIC adds control traffic packets to a specific queue, which does not receive any other kind of packets.
Currently, only ARP packets are filtered.
Other packets are distributed among the other queues, according to RSS.

### Forwarding

A worker responsible for controlling traffic (`worker_ct`) forwards the packets between the port and the virtual device.

### Virtual Device

LightingFilter automatically setups the virtual devices with the ethernet address of the corresponding port.
After LightingFilter completes the initialization, the virtual device must be configured manually.
