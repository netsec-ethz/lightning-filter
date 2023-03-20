#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Fabio Streun

set -Eeuo pipefail

pushd "$(dirname "$0")"

function wg_up() {
    sudo wg-quick up ./wg${side}.conf
}

function wg_down() {
    sudo wg-quick down ./wg${side}.conf
}

function usage() {
	echo "Usage:"
	echo "$0 up|down 1|2"
}

if [ $# -eq 0 ]
then
	echo "No argument provided."
	usage
	exit 1
fi

side=$2

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