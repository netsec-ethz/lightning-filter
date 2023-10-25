#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Fabio Streun

set -Eeuo pipefail

# end-host addresses
eh0_address="10.248.1.1"
eh1_address="10.248.2.1"

# lf address
lf00_address="10.248.1.10"
lf01_address="10.248.100.10"
lf10_address="10.248.2.10"
lf11_address="10.248.100.11"

# mac addresses of interfaces
eh0mac="00:76:65:74:68:13"
lf00mac="00:76:65:74:68:12"
lf01mac="00:76:65:74:68:11"
eh1mac="00:76:65:74:68:23"
lf10mac="00:76:65:74:68:22"
lf11mac="00:76:65:74:68:21"

# namespaces representing the different machines
lf0ns="lf0ns"
eh0ns="eh0ns"
eh1ns="eh1ns"
lf1ns="lf1ns"

# interface names
eh0="eh0"
lf00="lf00"
lf01="lf01"
eh1="eh1"
lf10="lf10"
lf11="lf11"