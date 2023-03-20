#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Fabio Streun

set -Eeuo pipefail

# main cores + keymanager core + 16 worker cores
EAL_lcores="-l 18-35"
EAL_allow="-a 0000:88:00.1"

# Address of interface
ip=172.31.116.131

# Address of gateway (potentially peer)
ethernet_neigh=3c:fd:fe:9e:8e:39

# Address of peer
ip_remote=172.31.116.130
