#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Fabio Streun

set -Eeuo pipefail

# include network variables
source "$(dirname "$0")/testnet_vars.sh"

# setup test network for one side
function net_up() {
	sudo ip netns add $lfxns
	sudo ip netns add $ehxns

	sudo ip link add $ehx address $ehxmac type veth peer name $lfx0 address $lfx0mac

	sudo ip link set dev $ehx netns $ehxns
	sudo ip link set dev $lfx0 netns $lfxns
	sudo ip link set dev $lfx1 netns $lfxns

	sudo ip -n $ehxns address add $ehx_address/24 dev $ehx

	sudo ip -n $ehxns link set dev $ehx up
	sudo ip -n $ehxns link set dev lo up

	sudo ip -n $lfxns link set dev $lfx0 up
	sudo ip -n $lfxns link set dev $lfx1 up

	sudo ip -n $lfxns link set dev lo up

	sudo ip -n $ehxns link set dev $ehx mtu 1420

	# set LF's internal address (lfx0) as default gateway for the endhost
	sudo ip -n $ehxns route add default via $lfx0_address
}

function testnet_up() {
	# set up the two outer network interfaces, which are connected to each other.
	sudo ip link add $lf01 address $lf01mac type veth peer name $lf11 address $lf11mac

	# network on side 0
	ehx_address=$eh0_address
	ehy_address=$eh1_address
	lfx0_address=$lf00_address
	lfxns=$lf0ns
	ehxns=$eh0ns
	ehx=$eh0
	lfx0=$lf00
	lfx1=$lf01
	ehxmac=$eh0mac
	ehymac=$eh1mac
	lfx0mac=$lf00mac
	lfx0mac=$lf01mac
	lfy1mac=$lf11mac

	net_up

	# network on side 1
	ehx_address=$eh1_address
	ehy_address=$eh0_address
	lfx0_address=$lf10_address
	lfxns=$lf1ns
	ehxns=$eh1ns
	ehx=$eh1
	lfx0=$lf10
	lfx1=$lf11
	ehxmac=$eh1mac
	ehymac=$eh0mac
	lfx0mac=$lf10mac
	lfx0mac=$lf11mac
	lfy1mac=$lf01mac

	net_up
}

function net_down() {
	sudo ip netns del $lf0ns
	sudo ip netns del $lf1ns
	sudo ip netns del $eh0ns
	sudo ip netns del $eh1ns
}

function testnet_down() {
	net_down
}

function cleanup() {
	set +eu pipefail

	echo "perform cleanup"

	sudo ip netns del $lf0ns
	sudo ip netns del $lf1ns
	sudo ip netns del $eh0ns
	sudo ip netns del $eh1ns

	sudo ip link delete $lf01
	sudo ip link delete $lf11
	sudo ip link delete $eh0
	sudo ip link delete $eh1
}

trap 'catch $? $LINENO' EXIT
catch() {
  if [ "$1" != "0" ]; then
		echo "Something Failed!"
    echo "Error $1 occurred on $2"
		cleanup
		exit 1
  fi
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
	testnet_up
elif [ "$up_down" = "down" ];
then
	testnet_down
else
	echo "First argument must either be up or down"
	usage
	exit 1
fi

exit 0