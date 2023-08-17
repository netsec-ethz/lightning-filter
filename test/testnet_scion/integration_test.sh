#!/usr/bin/env bash

set -Eo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

function usage() {
	echo "Usage:"
	echo "$0 lf_exec scion_dir"
}

if [ $# -eq 0 ]
then
	echo "No argument provided."
	usage
	exit 1
fi

# get executable from first argument
lfexec=$(realpath $1)

# get SCION binary directory from first argument
scion_dir=$(realpath $2)

function cleanup() {
	# TODO: kill application gracefully
	sudo tmux kill-session -t $TMUX_SESSION
	sleep 0.1

	# terminate SCION services
	$SCRIPT_DIR/scion/supervisor/supervisor.sh stop all
	sleep 0.1

	# tear down test network
	$SCRIPT_DIR/testnet.sh down
	sleep 0.1
}

# Always perform cleanup on exit
trap 'catch $? $LINENO' EXIT
catch() {
	cleanup
}

# go to current directory
pushd $SCRIPT_DIR > /dev/null

# Setup network, generate SCION topology, start SCION services, and start LF instances
TMUX_SESSION="lf_session"
./testnet.sh up
sleep 0.1
./scion/gen-topo.sh $scion_dir
./scion/supervisor/supervisor.sh reload
./scion/supervisor/supervisor.sh start all
sleep 1
sudo tmux new-session -d -s $TMUX_SESSION ./run_lf.sh $lfexec
sleep 5

# get one SCION ping before doing the tests
ping_res=1
counter=0
until [ $ping_res -eq 0 ]
do
	sudo ip netns exec far-0 $scion_dir/bin/scion ping -c 2 --sciond 10.248.3.1:30255 --dispatcher /run/shm/dispatcher/endhost1-ff00_0_111.sock 1-ff00:0:112,10.248.5.2
	ping_res=$?
	((counter++)) 
	if [ $counter -eq 5 ]
	then
		break
	fi
done

# Run tests and count failed tests
error=0

function test_scion_ping() {
	name=$1
	expected=$2
	sudo ip netns exec far-0 $scion_dir/bin/scion ping -c 2 --sciond 10.248.3.1:30255 --dispatcher /run/shm/dispatcher/endhost1-ff00_0_111.sock 1-ff00:0:112,10.248.5.2
	if [ $? -ne $expected ]; then
		echo "FAIL: $name"
		((error=error+1))
	else
		echo "PASS: $name"
	fi
}

# simple ping
test_scion_ping "simple_ping" 0

# set overall rate limit to 0
sudo ./../../usertools/lf-ipc.py -f lf0 --cmd="/ratelimiter/set" --params="-,-,0,0,0,0"
sleep 1
test_scion_ping "overall_rl_0" 1

# set rate limit to 1000 (pps and bps)
sudo ./../../usertools/lf-ipc.py -f lf0 --cmd="/ratelimiter/set" --params="-,-,1000,1000,1000,1000"
sleep 1
test_scion_ping "overall_rl_1000" 0

popd > /dev/null

# print test result and exit with the same value
echo Overall.............
if [ $error -ne 0 ]; then
	echo "FAIL: $error tests have failed"
else
	echo "PASS"
fi

exit $error