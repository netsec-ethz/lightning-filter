# IP Test Network Setup

The IP test network setup facilitates functional tests of the Lightning Filter (LF) on a single machine.

The setup consists of two LF machines and two end-hosts (EH) machines simulated using the four different namespaces lf0ns/lf1ns and eh0ns/eh1ns, respectively.

```
+-------+     +-------+        +-------+     +-------+
| eh0ns |     | lf0ns |        | lf1ns |     | eh1ns |
|       |     |       |        |       |     |       |
|      eh0---lf00   lf01------lf11   lf10---eh1      |
+-------+     +-------+        +-------+     +-------+
```

Each EH machine is connected to its corresponding LF machine, while these are directly connected to each other.
On both LF machines only the LF application under test is executed. On the EH machines arbitrary applications can be run.

IP addresses are distributed as follows:
```
End-Host 0:
   10.248.1.1
End-Host 1:
   10.248.2.1
```

## Network Setup

The command
```
./testnet.sh up
```
create all the used namespaces, interfaces and connection. Additionally, it also assigns IP addresses and configures routes.

The same script can also be used to remove all the created configurations with
```
./testnet.sh down
```

## Lightning Filter Setup

To run LF in the corresponding namespaces the script ``run_lf.sh`` can be used.
```
sudo ./run_lf.sh <path/to/lf_exec>
```
The script expects the LF executable as first parameter. The output of the running LF instances are redirected to the files ``logs/lf0.log`` and ``logs/lf1.log``.

E.g.:
```
sudo ./run_lf.sh ../../build/src/lf
```

Interrupting the script, will also terminate the LF instances.

Note: Build LightningFilter without checksum offloading as the TAP interfaces do not support it (apparently).

## Tests

To run a test command in a end-host's namespace the following command can be used:
```
sudo ip netns exec eh0ns <test_command>
```

E.g., to test ping:
```
sudo ip netns exec eh0ns ping 10.248.2.1
```
or for the other direction:
```
sudo ip netns exec eh1ns ping 10.248.1.1
```

To test the connection with a simple TCP echo server, ncat can be used.
Server:
```
sudo ip netns exec eh1ns ncat -l 2000 -k -c 'xargs -n1 echo'
```
Client:
```
sudo ip netns exec eh0ns ncat 10.248.2.1 2000
```

### Integration Test

The integration test script `integration_test.sh` a ping message can be transmitted between the two end-hosts with LightningFilter protection.
Therefore, the scripts sets up the test network, and starts the LightingFilter. After testing a ping, the LightningFilter are stopped, and the test network is closed.

```
./integration_test.sh ../../build/src/lf
```

## WireGuard Setup
To setup WireGuard between the end hosts (over the LightningFilter), the following command can be used:
```
./wg/wg.sh up
```

To test the WireGuard connection use ping:
```
sudo ip netns exec eh0ns ping 10.0.0.2
sudo ip netns exec eh1ns ping 10.0.0.1
```


## Debugging

### Packet Capturing

#### Using tcpdump:

```
sudo ip netns exec eh0ns tcpdump -i eh0
```

#### Using Wireshark over SSH:
(requires passwordless sudo on remote)
Remote capture command: `sudo ip netns exec lf1ns tcpdump -U -nni lf11 -w -`