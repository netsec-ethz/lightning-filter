#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Fabio Streun

set -Eeuo pipefail

# include local variables
source "$(dirname "$0")/local_vars.sh"

tmux_session="lfSession"

function lf_up(){
    tmux new-session -d -s "$tmux_session" ./run_lf_vdev.sh $lfexec $side
    echo Attach to tmux session:
    echo tmux attach-session -t $tmux_session
    echo Kill tmux session:
    echo tmux kill-session -t $tmux_session
}

function route_up(){
    sudo ip addr add $ip/32 dev lf0
	sudo ip link set dev lf0 up
    # route everything to 10.248.2.0/24 to lf0 (via the device 10.248.2.1)
    sudo ip route add $ip_remote/32 dev lf0
    # set ethernet address of device 10.248.2.1 
    sudo ip neigh add $ip_remote lladdr $ethernet_neigh dev lf0

    sudo ip link set dev lf0 mtu 1420
}

function cleanup() {
	set +eu pipefail
	tmux kill-session $tmux_session
}

trap 'catch $? $LINENO' EXIT
catch() {
	if [ "$1" = "0" ]; then
		echo "Finished Setup"
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

# execute lightning filter
side=$2

if [ $side -eq 1 ]
then
	lf_up
elif [ $side -eq 2 ]
then
	lf_up
else
	echo "Second argument defines the side (1 or 2)"
	exit 1
fi

sleep 2
route_up

# wait for interrupt
wait

exit 0

