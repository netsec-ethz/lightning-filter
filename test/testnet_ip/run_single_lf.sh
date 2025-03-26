#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Fabio Streun

set -Eeuo pipefail

log_folder="logs/"

# The packet processing is by default IP, but can be set with an environment variable.
pkt_processing=${LF_PKT_PROCESSING:-"ip"}

# include network variables
source "$(dirname "$0")/testnet_vars.sh"

function lf_up() {
		echo "ip netns exec $lfxns $lfexec ... $log_file"
		sudo ip netns exec $lfxns $lfexec --lcores=$lcores --no-huge \
		--vdev=net_tap0,remote=$lfx0 \
		--vdev=net_tap1,remote=$lfx1 \
		--file-prefix=$file_prefix \
		--log-level lf:debug \
		--\
		--version \
		-p 0x3 \
		--portmap "(0,1,o),(1,0,i)" \
		-c $lf_config \
		--processing $pkt_processing \
		--bf-period 500 \
		--bf-hashes 7 \
		--bf-bytes 131072 \
		2> $log_file
}

function lfs_up() {
	lfxns=$lf0ns
	lfx0=$lf00
	lfx1=$lf01
	lf_config="config/lf1.json"
	lcores="(0-3)@0"
	file_prefix="lf0"
	log_file="${log_folder}lf0.log"

	lf_up
}

function cleanup() {
	set +eu pipefail
}

trap 'catch $? $LINENO' EXIT
catch() {
	if [ "$1" = "0" ]; then
		echo "Terminated - consult log files for info"
	elif [ "$1" = "130" ]; then
		echo "Received Interrupt"
		exit 0
  else
		echo "Something Failed!"
    echo "Error $1 occurred on $2"
		cleanup
		exit 1
  fi
}

function usage() {
	echo "Usage:"
	echo "$0 lf_exec"
}

if [ $# -eq 0 ]
then
	echo "No argument provided."
	usage
	exit 1
fi

# get executable from first argument
lfexec=$1

# create log folder if not exists
mkdir -p -- "$log_folder"

# execute lightning filter applications
lfs_up

# wait for interrupt
wait

exit 0