#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Fabio Streun

set -Eeuo pipefail

log_folder="logs/"

# include network variables
# source "$(dirname "$0")/testnet_vars.sh"

function lf_up() {
		echo "ip netns exec $lfxns $lfexec ... $log_file"
		sudo ip netns exec $lfxns $lfexec --lcores=$lcores --no-huge \
		--vdev=net_tap0,remote=$lfx0 \
		--vdev=net_tap1,remote=$lfx1 \
		--file-prefix=$file_prefix \
		--log-level lf:debug \
		--\
		-p 0x3 \
		--portmap "(0,1,i),(1,0,o)" \
		-c $lf_config \
		--bf-period 500 \
		--bf-hashes 7 \
		--bf-bytes 131072 \
		2> $log_file
}

function lfs_up() {
	if [ $instance = 0 ]; then
	lfxns=near-0
	lfx0=two
	lfx1=three
	lf_config="config/lf_1_ff00_0_111.json"
	lcores="(0-3)@0"
	file_prefix="lf0"
	log_file="${log_folder}lf0.log"

	lf_up

	elif [ $instance = 1 ]; then

	lfxns=near-1
	lfx0=six
	lfx1=seven
	lf_config="config/lf_1_ff00_0_112.json"
	lcores="(0-3)@1"
	file_prefix="lf1"
	log_file="${log_folder}lf1.log"

	lf_up
	
	else
	echo "Unknown instance number $instance. Must be 0 or 1"
	fi
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
	echo "$0 <lf_exec> <instance>"
}

if [ $# -eq 0 ]
then
	echo "No argument provided."
	usage
	exit 1
fi

# get executable from first argument
lfexec=$1

# get instance number {0,1} from second argument
instance=$2

# create log folder if not exists
mkdir -p -- "$log_folder"

# execute lightning filter applications
lfs_up

# wait for interrupt
wait

exit 0