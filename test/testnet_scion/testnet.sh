#!/usr/bin/env bash
set -Eeuo pipefail

function testnet_up() {
    ######################
    # Setup namespaces
    ######################

    sudo ip netns add near-0
    sudo ip netns add far-0

    sudo ip netns add near-1
    sudo ip netns add far-1

    ######################
    # Setup links and ports
    ######################

    sudo ip link add one address 00:76:65:74:68:31 type veth peer name two address 00:76:65:74:68:32
    sudo ip link add three address 00:76:65:74:68:33 type veth peer name four address 00:76:65:74:68:34

    sudo ip link add five address 00:76:65:74:68:35 type veth peer name six address 00:76:65:74:68:36
    sudo ip link add seven address 00:76:65:74:68:37 type veth peer name eight address 00:76:65:74:68:38

    sudo ip link add infra1 address 00:56:45:54:48:31 type veth peer name infra2 address 00:56:45:54:48:32
    sudo ip link add infra5 address 00:56:45:54:48:35 type veth peer name infra6 address 00:56:45:54:48:36

    ######################
    # Assign ports to namespaces
    ######################

    sudo ip link set dev two netns near-0
    sudo ip link set dev three netns near-0
    sudo ip link set dev four netns far-0

    sudo ip link set dev infra2 netns near-0

    sudo ip link set dev six netns near-1
    sudo ip link set dev seven netns near-1
    sudo ip link set dev eight netns far-1

    sudo ip link set dev infra6 netns near-1


    ######################
    # IP Addresses
    ######################

    sudo ip address add 10.248.1.1/24 dev one
    sudo ip netns exec near-0 ip address add 10.248.1.2/24 dev two
    sudo ip netns exec near-0 ip address add 10.248.2.1/24 dev three
    sudo ip netns exec far-0 ip address add 10.248.2.2/24 dev four
    sudo ip netns exec far-0 ip address add 10.248.3.1/24 dev lo

    sudo ip address add 10.248.7.1/24 dev infra1
    sudo ip netns exec near-0 ip address add 10.248.7.2/24 dev infra2

    sudo ip address add 10.248.4.1/24 dev five
    sudo ip netns exec near-1 ip address add 10.248.4.2/24 dev six
    sudo ip netns exec near-1 ip address add 10.248.5.1/24 dev seven
    sudo ip netns exec far-1 ip address add 10.248.5.2/24 dev eight
    sudo ip netns exec far-1 ip address add 10.248.6.1/24 dev lo

    sudo ip address add 10.248.8.1/24 dev infra5
    sudo ip netns exec near-1 ip address add 10.248.8.2/24 dev infra6


    ######################
    # UP
    ######################

    sudo ip link set dev one up
    sudo ip netns exec near-0 ip link set dev two up
    sudo ip netns exec near-0 ip link set dev three up
    sudo ip netns exec far-0 ip link set dev four up
    sudo ip netns exec far-0 ip link set dev lo up

    sudo ip link set dev infra1 up
    sudo ip netns exec near-0 ip link set dev infra2 up

    sudo ip link set dev five up
    sudo ip netns exec near-1 ip link set dev six up
    sudo ip netns exec near-1 ip link set dev seven up
    sudo ip netns exec far-1 ip link set dev eight up
    sudo ip netns exec far-1 ip link set dev lo up

    sudo ip link set dev infra5 up
    sudo ip netns exec near-1 ip link set dev infra6 up



    ##################################################################
    # Routing and ARP entries
    ##################################################################

    ######################
    # main namespace
    ######################

    sudo ip route add 10.248.2.0/24 dev one via 10.248.1.2
    sudo ip route add 10.248.3.0/24 dev one via 10.248.1.2
    # ethernet address: static arp entry for .1.2
    # if LF supports ethernet translation: sudo arp -s 10.248.1.2 00:76:65:74:68:32
    sudo arp -s 10.248.1.2 00:76:65:74:68:34 # skip LF mac

    sudo ip route add 10.248.5.0/24 dev five via 10.248.4.2
    sudo ip route add 10.248.6.0/24 dev five via 10.248.4.2
    # ethernet address: static arp entry for .4.2
    # if LF supports ethernet translation: sudo arp -s 10.248.4.2 00:76:65:74:68:36
    sudo arp -s 10.248.4.2 00:76:65:74:68:38 # skip LF mac

    ######################
    # near-0 and far-0
    ######################

    sudo ip netns exec near-0 ip route add 10.248.4.0/24 dev two via 10.248.1.1
    sudo ip netns exec near-0 ip route add 10.248.5.0/24 dev two via 10.248.1.1
    sudo ip netns exec near-0 ip route add 10.248.6.0/24 dev two via 10.248.1.1
    # ethernet address: LF config for peer

    sudo ip netns exec near-0 ip route add 10.248.3.0/24 dev three via 10.248.2.2
    # ethernet address: LF config for backend

    # this should be automatic...?
    #sudo ip netns exec near-0 ip route change 10.248.1.0/24 dev two via 10.248.1.1
    #sudo ip netns exec near-0 ip route change 10.248.2.0/24 dev three via 10.248.2.2

    sudo ip netns exec far-0 ip route add 10.248.1.0/24 dev four via 10.248.2.1
    sudo ip netns exec far-0 ip route add 10.248.4.0/24 dev four via 10.248.2.1
    sudo ip netns exec far-0 ip route add 10.248.5.0/24 dev four via 10.248.2.1
    # sudo ip netns exec far-0 ip route add 10.248.6.0/24 dev four via 10.248.2.1 SIG routes this address!

    sudo ip netns exec far-0 ip route add 10.248.7.0/24 dev four via 10.248.2.1

    # ethernet address: static arp entry for .2.1
    # if LF supports ethernet translation: sudo ip netns exec far-0 arp -s 10.248.2.1 00:76:65:74:68:33
    sudo ip netns exec far-0 arp -s 10.248.2.1 00:76:65:74:68:31 # skip LF mac


    ######################
    # near-1 and far-1
    ######################

    sudo ip netns exec near-1 ip route add 10.248.1.0/24 dev six via 10.248.4.1
    sudo ip netns exec near-1 ip route add 10.248.2.0/24 dev six via 10.248.4.1
    sudo ip netns exec near-1 ip route add 10.248.3.0/24 dev six via 10.248.4.1
    # ethernet address: LF config for peer

    sudo ip netns exec near-1 ip route add 10.248.6.0/24 dev seven via 10.248.5.2
    # ethernet address: LF config for backend

    # this should be automatic...?
    #sudo ip netns exec near-1 ip route change 10.248.4.0/24 dev six via 10.248.4.1
    #sudo ip netns exec near-1 ip route change 10.248.5.0/24 dev seven via 10.248.5.2

    sudo ip netns exec far-1 ip route add 10.248.1.0/24 dev eight via 10.248.5.1
    sudo ip netns exec far-1 ip route add 10.248.2.0/24 dev eight via 10.248.5.1
    # sudo ip netns exec far-1 ip route add 10.248.3.0/24 dev eight via 10.248.5.1 SIG routes this address!
    sudo ip netns exec far-1 ip route add 10.248.4.0/24 dev eight via 10.248.5.1

    sudo ip netns exec far-1 ip route add 10.248.8.0/24 dev eight via 10.248.5.1
    # ethernet address: static arp entry for .5.1
    # if LF supports ethernet translation: sudo ip netns exec far-1 arp -s 10.248.5.1 00:76:65:74:68:37
    sudo ip netns exec far-1 arp -s 10.248.5.1 00:76:65:74:68:35 # skip LF mac
}

function testnet_down() {
    set +eu pipefail

    sudo ip netns del far-0
    sudo ip netns del near-0

    sudo ip link del infra1

    sudo ip netns del far-1
    sudo ip netns del near-1

    sudo ip link del infra5

    sudo arp -d 10.248.1.2
    sudo arp -d 10.248.4.2
}

function cleanup() {
    testnet_down
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