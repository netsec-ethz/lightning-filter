# Performance Test Network Setup

A performance test setup for LightningFilter consists of two machines that are directly connected to each other.
One machine, the DUT, runs LightningFilter. The other machine generates traffic transmits it to the DUT and analyses the response.

```
+---------+     +-------+
|traffic- |     |  LF   |
|generator|---->|       |
|         |<----|       |
+---------+     +-------+
```

## Starting Lightning Filter Traffic Test

To run LF the script ``run_lf.sh`` can be used.
```
sudo ./run_lf.sh <path/to/lf_exec>
```

The script expects the LF executable as the first parameter. The output of the running LF instance is redirected to the file ``logs/lf0.log``.

E.g.:
```
sudo ./run_lf.sh ../../build/src/lf
```