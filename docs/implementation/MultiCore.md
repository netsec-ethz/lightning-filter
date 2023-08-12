# Multi-Core

To prevent overloading of a single core, while other cores still have processing capacity, multiple mechanisms ensure that the workload can be distributed among multiple cores.
LightningFilter supports RSS, which is a common packet processing distribution mechanism implemented on the NIC.

> Note: Distributor cores, as discribed in the following, are currently not implemented.

Alternatively, also dedicated distribution cores can be activated. When activated, these distributors, instead of the workers, poll packets from the rx queues and put them into the tx queues.
The distribution cores distributed the packets evenly among all workers for the processing of packets.
Per default, packet order is preserved (at least per-flow).
This approach ensures that a single core cannot be overwhelmed by a single flow (maliciously or not).

The number of distributors, i.e., lcores, must be defined with the application parameter `--dist-cores`.

## The Distributor Implementation in Detail

With the distributor mechanism, 'n' cores are allocated as distributor cores. Each distributor core is assigned one port pair, i.e., one rx queue and one tx queue, and a set of workers.

When receiving packets, the distributor adds packets to different per-worker receive queues in a round-robin fashion. Each worker polls packets from its receive queue, processes them, and passes them back to the distributor, including the processing results through another queue. The distributors then forward the packets to the dedicated port or drop the packet.

![Image](multicore_distributor.drawio.svg "icon")

Because the distributors poll packets from different workers as soon as they are in the queue, packet order might be changed, which is suboptimal for some network protocols. Therefore, packet order is re-established before they are transmitted by utilizing the reorder buffer library provided by DPDK.
To reduce the overhead of the reorder buffer in terms of memory and packet latency, the size of the reorder buffer is kept small. A small reorder buffer might not be able to ensure packet order when packets arrive a lot earlier or a lot later. This can happen when the variance of packet processing time is large. However, since with LF the packet processing time is rather constant and the variance rather small, this should not occur too often. In short, packet order is ensured as well as possible without introducing unnecessary overhead.
