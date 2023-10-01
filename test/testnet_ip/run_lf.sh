#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Fabio Streun

set -Eeuo pipefail

# The log directory is either given as environment variable or defaults to logs/
log_dir=${LF_LOG_DIR:-"logs/"}

# include network variables
source "$(dirname "$0")/testnet_vars.sh"

function lf_up() {
		echo "ip netns exec $lfxns $lfexec ... $log_file"
		sudo ip netns exec $lfxns $lfexec --lcores=$lcores --no-huge \
		--vdev=net_tap0,remote=$lfx0 \
		--vdev=net_tap1,remote=$lfx1 \
		--file-prefix=$file_prefix \
		--log-level lf:debug \
		-- \
		--version \
		-p 0x3 \
		--portmap "(0,1,o),(1,0,i)" \
		-c $lf_config \
		--bf-period 500 \
		--bf-hashes 7 \
		--bf-bytes 131072 \
		--disable-mirrors \
		&> $log_file \
		&
	lf_pid=$!
}

function lfs_up() {
	lfxns=$lf0ns
	lfx0=$lf00
	lfx1=$lf01
	lf_config="config/lf1.json"
	lcores="(0-5)@0"
	file_prefix="lf0"
	log_file="${log_dir}/lf0.log"

	lf_up

	lf0_pid=$lf_pid

	lfxns=$lf1ns
	lfx0=$lf10
	lfx1=$lf11
	lf_config="config/lf2.json"
	lcores="(0-5)@1"
	file_prefix="lf1"
	log_file="${log_dir}/lf1.log"

	lf_up

	lf1_pid=$lf_pid
}

function cleanup() {
	set +eu pipefail
	sudo kill $lf0_pid
	sudo kill $lf1_pid
}

trap 'catch $? $LINENO' EXIT
catch() {
	cleanup
	if [ "$1" = "0" ]; then
		echo "Terminated - consult log files for info"
	elif [ "$1" = "130" ]; then
		echo "Received Interrupt"
		exit 0
	else
		echo "Something Failed!"
		echo "Error $1 occurred on $2"
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
mkdir -p -- "$log_dir"

# execute lightning filter applications
lfs_up

# wait for interrupt
wait

exit 0