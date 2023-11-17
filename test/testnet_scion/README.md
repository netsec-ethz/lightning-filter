# SCION Test Network Setup

## Test Network


```
+-------+     +-------+        +-------+     +-------+
| far-0 |     | near-0|        | near-1|     | far-1 |
|       |     |       |        |       |     |       |
|      one---two     three----four   five---six      |
+-------+     +---|---+        +---|---+     +-------+
                infra2           infra6
                  |                |
                  |                |
                infra1           infra5
                  |                |
```

TODO (addresses)

To setup the network run
```
./testnet.sh up
```

To remove the network run
```
./testnet.sh down
```

## SCION
The LightningFilter documentation provides instructions to install SCION on a machine (see [docs/SCION.md](../../docs/SCION.md)).

For the test setup the following SCION modules are required:
control service (control), border router (router), dispatcher (dispatcher), daemon (daemon), and the PKI (scion-pki), and SCION tools like ping (scion).

For that run following code in the SCION directory:
```
go build -o ./bin/ ./control/cmd/control
go build -o ./bin/ ./daemon/cmd/daemon
go build -o ./bin/ ./dispatcher/cmd/dispatcher
go build -o ./bin/ ./router/cmd/router
go build -o ./bin/ ./scion/cmd/scion
go build -o ./bin/ ./scion-pki/cmd/scion-pki
```

Optionally also build the SIG:
```
go build -o ./bin/ ./gateway/cmd/gateway
```

### SCION Topology

To generate the SCION topology and run the test setup the following dependencies have to be installed:
```
sudo apt-get install -y python3-pip supervisor
pip3 install plumbum toml supervisor-wildcards
```
Note that for this test setup supervisord has to be run as root. Therefore, `supervisor-wildcards` has to be accessible to root (and not just the user).

The script `gen-topo.sh` generates all the necessary credentials and configuration files, and stores them in the directories `gen` and `gen-eh`.
The script requires the location of the SCION source directory and assumes that the binaries of the required modules are located in the source's `bin` directory:
```
./scion/gen-topo.sh ~/scion
```

To start the SCION modules run
```
./scion/supervisor/supervisor.sh reload
./scion/supervisor/supervisor.sh start all
```

To stop the SCION modules run
```
./scion/supervisor/supervisor.sh stop all
```

The logs of the modules are located in `scion/logs`.

#### Explanation
For the test setup, the SCION topology generated the required configuration files.
The configuration files have then been adjusted to work with the namespaces and are stored in the directories `supervisor`, `gen_template`, and `gen-eh_template`.

The script `gen-topo.sh` generate all the necessary credentials with the topology generator and combines them with the template configurations.

I am not sure why the dispatcher has to be run as root...
Also everything executed in the namespaces could be run as non-root.
E.g., with `sudo -u $USER ...` or by using `nsenter` with `setuid` and `setguid` parameters.


## LightningFilter
To run LF in the corresponding namespaces the script ``run_lf.sh`` can be used.

> NOTE that your system should have at least 4 cores s.t. each LF can have its own core and you can still perform pings. If the logs say that there are no cores available then this might be the issue.
```
./run_lf.sh <path/to/lf_exec>
```
The script expects the LF executable as first parameter. The output of the running LF instances are redirected to the files ``logs/lf0.log`` and ``logs/lf1.log``.

E.g.:
```
sudo ./run_lf.sh ../../build/src/lf
```

Interrupting the script, will also terminate the LF instances.

## Tests

### SCION Ping
Install the scion module:
```
go build -o ./bin/ ./go/scion/
```

SCION ping (IPv4) with LF:
```
sudo ip netns exec far-0 /home/ubuntu/scion/bin/scion ping --sciond 10.248.3.1:30255 --dispatcher /run/shm/dispatcher/endhost1-ff00_0_111.sock 1-ff00:0:112,10.248.5.2

sudo ip netns exec far-1 /home/ubuntu/scion/bin/scion ping --sciond 10.248.6.1:30255 --dispatcher /run/shm/dispatcher/endhost1-ff00_0_112.sock 1-ff00:0:111,10.248.2.2
```

SCION ping (IPv6) with LF:
```
sudo ip netns exec far-0 /home/ubuntu/scion/bin/scion ping --sciond [fd00:f00d:cafe::3:1]:30255 --dispatcher /run/shm/dispatcher/endhost1-ff00_0_111.sock 1-ff00:0:112,[fd00:f00d:cafe::5:2]

sudo ip netns exec far-1 /home/ubuntu/scion/bin/scion ping --sciond [fd00:f00d:cafe::6:1]:30255 --dispatcher /run/shm/dispatcher/endhost1-ff00_0_112.sock 1-ff00:0:111,[fd00:f00d:cafe::2:2]
```

SCION ping (IPv4) without LF (only in main namespace):
```
# from main AS 1-ff00:0:110
~/scion/bin/scion ping --sciond 127.0.0.13:30255 --dispatcher /run/shm/dispatcher/default.sock 1-ff00:0:112,10.248.4.1
~/scion/bin/scion ping --sciond 127.0.0.13:30255 --dispatcher /run/shm/dispatcher/default.sock 1-ff00:0:111,10.248.1.1

# from AS 1-ff00:0:111
~/scion/bin/scion ping --sciond 127.0.0.20:30255 --dispatcher /run/shm/dispatcher/default.sock 1-ff00:0:112,10.248.4.1
~/scion/bin/scion ping --sciond 127.0.0.20:30255 --dispatcher /run/shm/dispatcher/default.sock 1-ff00:0:111,10.248.1.1
```

SCION ping (IPv6) without LF (only in main namespace):
```
# from main AS 1-ff00:0:110
~/scion/bin/scion ping --sciond [fd00:f00d:cafe::7f00:d]:30255 --dispatcher /run/shm/dispatcher/default.sock 1-ff00:0:112,[fd00:f00d:cafe::4:1]
~/scion/bin/scion ping --sciond [fd00:f00d:cafe::7f00:d]:30255 --dispatcher /run/shm/dispatcher/default.sock 1-ff00:0:111,[fd00:f00d:cafe::1:1]
```

### Ping through SIG

```
sudo ip netns exec far-0 ping 10.248.6.1
sudo ip netns exec far-1 ping 10.248.3.1
```

### Ping through WireGuard
Setup WireGuard:
```
./wg/wg.sh up
```

```
sudo ip netns exec far-0 ping 10.0.0.2
sudo ip netns exec far-1 ping 10.0.0.1
```

Turn down WireGuard:
```
./wg/wg.sh down
```

### Integration Test

The integration test script `integration_test.sh` a ping message can be transmitted between the two end-hosts with LightningFilter protection.
Therefore, the scripts sets up the test network, starts the SCION services and the LightingFilter. After testing a SCION ping, the LightningFilter and SCION services are stopped, and the test network is closed.

Note that the SCION configuration is always freshly generated.

E.g.:

```
./integration_test.sh ../../build/src/lf ~/scion/
```

## Troubleshooting

### Wireshark

Capture Command
```
sudo ip netns exec far-0 tcpdump -i four -U -w -
```
