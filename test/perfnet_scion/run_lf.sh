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
		--log-level lf:notice \
		--\
		-p 0x1 \
		--portmap "(0,0)" \
		-c $lf_config \
		--bf-nb 2 \
		--bf-period 1000 \
		--bf-hashes 13 \
		--bf-bytes 33554432 \
		--rl-size 12000 \
		--km-size 12000 \
		2> $log_file
}

function lfs_up() {
	lf_config="config/lf0_p10000.json" # config with 10000 peers
	#lf_config="config/lf0.json" # config with 1 peer
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

# execute lightning filter
lfs_up

# wait for interrupt
wait

exit 0