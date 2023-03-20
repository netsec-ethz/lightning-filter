#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Fabio Streun

set -Eeuo pipefail

log_folder="logs/"

# include local variables
source "$(dirname "$0")/local_vars.sh"

function lf_up() {
		echo "$lfexec ... $log_file"
		sudo $lfexec $EAL_lcores $EAL_allow \
		--log-level lf:debug \
		--vdev=virtio_user0,path=/dev/vhost-net,queues=8,iface=lf0,mac=00:64:74:61:70:11 \
		--file-prefix=$file_prefix \
		--\
		-p 0x3 \
		--portmap "(0,1,i),(1,0,o)" \
		-c $lf_config \
		--bf-nb 2 \
		--bf-period 1000 \
		--bf-hashes 13 \
		--bf-bytes 33554432 \
		2> $log_file
}

function lf1_up() {
	lf_config="config/lf1.json"
	log_file="${log_folder}lf1.log"
	file_prefix="lf1"

	lf_up
}

function lf2_up() {
	lf_config="config/lf2.json"
	log_file="${log_folder}lf2.log"
	file_prefix="lf2"

	lf_up
}

function cleanup() {
	set +eu pipefail
	kill $lf_pid
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
	echo "$0 lf_exec {1,2}"
}

if [ $# -ne 2 ]
then
	echo "No argument provided."
	usage
	exit 1
fi

# get executable from first argument
lfexec=$1



# create log folder if not exists
mkdir -p -- "$log_folder"

# execute lightning filter
side=$2
if [ $side -eq 1 ]
then
	lf1_up
elif [ $side -eq 2 ]
then
	lf2_up
else
	echo "Second argument defines the side (1 or 2)"
	exit 1
fi

# wait for interrupt
wait

exit 0