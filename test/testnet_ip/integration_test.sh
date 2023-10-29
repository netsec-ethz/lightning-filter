#!/usr/bin/env bash

set -Eo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

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

function cleanup() {
	# TODO: kill application gracefully
	tmux kill-session -t $TMUX_SESSION
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

# get executable from first argument
lfexec=$(realpath $1)

# go to current directory
pushd $SCRIPT_DIR > /dev/null

# Setup network and start LF instances
TMUX_SESSION="lf_session"
./testnet.sh up
sleep 0.1
tmux new-session -d -s $TMUX_SESSION ./run_lf.sh $lfexec
sleep 1

# Run tests and count failed tests
error=0

# The init ping is to make sure the interface is up and running
# before we start testing other things.
# Due to neighbor discovery, the first ping may take longer than
# the rest, so we ping once every second until the first ping succeeds.
# After 60 unsuccessful tries, we fail the test.
function init_ping() {
	name="init_ping"

	# ping until success or 60 tries
	for i in {1..60}; do
		sudo ip netns exec eh0ns ping -c1 10.248.2.1
		result=$?
		if [ $result -eq 0 ]; then
			echo "PASS: $name"
			return
		fi
	
		sleep 1
	done

	echo "FAIL: $name"
	((error=error+1))
}

function test_ping() {
	name=$1
	expected=$2
	sudo ip netns exec eh0ns ping -c2 10.248.2.1
	result=$?
	if [ $result -ne $expected ]; then
		echo "FAIL: $name, expected: $expected, actual: $result"
		((error=error+1))
	else
		echo "PASS: $name"
	fi
}

# init ping
init_ping

if [[ -z "${LF_IT_NO_RL}" ]]; then
# set overall rate limit to 0
sudo ./../../usertools/lf-ipc.py -f lf0 --cmd="/ratelimiter/set" --params="-,-,0,0,0,0"
sleep 1
test_ping "overall_rl_0" 1

# set rate limit to 1000 (pps and bps)
sudo ./../../usertools/lf-ipc.py -f lf0 --cmd="/ratelimiter/set" --params="-,-,1000,1000,1000,1000"
test_ping "overall_rl_1000" 0
fi

popd > /dev/null

# print test result and exit with the same value
echo Overall.............
if [ $error -ne 0 ]; then
	echo "FAIL: $error tests have failed"
else
	echo PASS
fi

exit $error