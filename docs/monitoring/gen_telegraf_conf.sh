#!/bin/bash

# Number of workers (default: 32)
nb_worker=${1:-32}
# DPDK file prefix (default: rte)
dpdk_file=${2:-rte}

rm telegraf.conf
cp telegraf.conf.templ telegraf.conf

sed -i "s|\(socket_path = \"/var/run/dpdk/\)rte\(/dpdk_telemetry.v2\"\)|\1$dpdk_file\2|" telegraf.conf

for ((worker_id=nb_worker-1; worker_id>=0; worker_id--))
do
    sed -i "s|\(\"/lf/worker/stats\"\)|\1,\"/lf/worker/stats,$worker_id\"|" telegraf.conf
done
