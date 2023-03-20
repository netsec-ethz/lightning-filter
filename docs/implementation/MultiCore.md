# Multi-Core

To prevent a single core to become overloaded, while other cores still have processing capacity, multiple mechanisms ensure that the work load is distributed among multiple cores.
LightningFilter supports RSS, which is a common packet processing distribution mechanisms implemented on the NIC. In addition, also dedicated distribution cores can be activated. When activated, these distributors, instead of the workers, poll packets from the rx queues and puts them into the tx queues. For the processing, the packets are distributed evenly among all workers. Per default, the distributors also ensure that the packet order is preserved (at least per-flow). This approach ensures that single core cannot be overwhelmed by a single flow (maliciously or not), as it is possible when only relying on RSS.

The distributor mechanism can be activated by setting the `LF_DISTRIBUTOR` cmake value:
```
cmake ../ -D LF_DISTRIBUTOR=ON
```

The number of distributors, i.e., lcores, must be defined with the application parameter `--dist-cores`.

## The Distributor Implementation in Detail

With the distributor mechanism, 'n' cores are allocated as distributor cores. Each distributor core is assigned one port pair, i.e., one rx queue and one tx queue, and a set of workers.

When receiving packets, the distributor adds packets to different per-worker receive queues in a round-robin fashion. Each worker polls packets from its receive queue, processes them and pass them back to the distributor including the processing results through another queue. The distributors then either forwards the packets to the dedicated port and drops the packet.

![Image](multicore_distributor.drawio.svg "icon")

Because the distributors poll packets from different workers as soon as they are in the queue, packet order might be changed, which is suboptimal for certain network protocols. Therefore, packet order is reestablished before they are transmitted by utilizing the reorder buffer library provided by DPDK.
To reduce the overhead of the reorder buffer in terms of memory and packet latency, the size of the reorder buffer is kept small. A small reorder buffer might not be able to ensure packet order when packets arrive a lot earlier or a lot later than. This can happen when the variance of packet processing time is large. However, since with LF the packet processing time is rather constant and the variance rather small, this should not occur too often. In short, packet order is ensured as good as possible without introducing unnecessary overhead.

The reorder mechanism can be disabled by setting the `LF_DISTRIBUTOR_REORDER` cmake value to `OFF`:
```
cmake ../ -D LF_DISTRIBUTOR_REORDER=OFF
```