# Lightning-Filter Monitoring System

The lf-monitor collects and stores metrics from the Lightning-Filter system and
provides a prometheus API endpoint for querying the metrics.
It is a standalone service written in Rust.

## Running the service

You can compile and run the service using the following commands:

```bash
cargo build
sudo ./target/debug/lf-monitor --dpdk-file-prefix lf0
```

Replace `lf0` with the correct dpdk file prefix for your running Lightning-Filter instance.

Note: We do not recommend running the service with `cargo run` because you should
not run cargo as root.

## Dependencies

To run the rust code or compile it, you need to have the rust toolchain installed.
You can install the rust toolchain using the following command:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
