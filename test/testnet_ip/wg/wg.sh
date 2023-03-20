#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Fabio Streun

set -Eeuo pipefail

pushd "$(dirname "$0")"
# include network variables
source "../testnet_vars.sh"

function wg_up() {
    sudo ip netns exec $eh0ns wg-quick up ./wg1.conf
    sudo ip netns exec $eh1ns wg-quick up ./wg2.conf
}

function wg_down() {
    sudo ip netns exec $eh0ns wg-quick down ./wg1.conf
    sudo ip netns exec $eh1ns wg-quick down ./wg2.conf
}

function usage() {
	echo "Usage:"
	echo "$0 up|down"
}

if [ $# -eq 0 ]
then
	echo "No argument provided."
	usage
	exit 1
fi

up_down=$1
if [ "$up_down" = "up" ];
then
	wg_up
elif [ "$up_down" = "down" ];
then
	wg_down
else
	usage
	exit 1
fi

popd

exit 0