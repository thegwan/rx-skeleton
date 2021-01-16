# rx-skeleton

This repository contains skeleton code for benchmarking packet RX throughput with DPDK written in C and in Rust. Currently the only application is `simple-count`, which counts the total number of packets received, and the total number of packets received per RX queue.

## Prerequisites
These applications are meant to be run on a multi-core Linux server with a Mellanox CX-5 adapter. More interfaces are ok, but for simplicity these assume that port index 0 is on the Mellanox card.

Build and install [DPDK 20.11](https://core.dpdk.org/download/) on your system. See the [Getting Started Guide](https://doc.dpdk.org/guides/linux_gsg/index.html) for more details. This will also require installing the MLNX_OFED (tested on version 5.1-2.5.8.0).

Set the `DPDK_PATH` environment variable to the DPDK installation directory, and set `LD_LIBRARY_PATH` to `$DPDK_PATH/lib/x86_64-linux-gnu`.

## Building and Running
Each application binary takes DPDK EAL parameters to select the list of cores to run on (`-l`) and the number of memory channels to use  (`-n`). Be sure to only use consecutive core IDs, as both apps default to core `0` as the main core, and cores `1` through `N` as the N worker cores. Each worker core maps to a single RX queue. The following examples use cores 0 through 4 and 6 memory channels. 

### C
```
make
sudo ./build/simple-count -l 0-4 -n 6
```

### Rust
```
cargo build --release
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH ./target/release/simple_count -l 0-4 -n 6
```
Ctrl-c to stop execution and display statistics.

