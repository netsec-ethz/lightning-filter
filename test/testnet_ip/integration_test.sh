#!/usr/bin/env bash

set -Euo pipefail

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

# get executable from first argument
lfexec=$(realpath $1)

function cleanup() {
	# TODO: kill application gracefully
	sudo tmux kill-session -t $TMUX_SESSION
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

TMUX_SESSION="lf_session"

./testnet.sh up
sleep 0.1

sudo tmux new-session -d -s $TMUX_SESSION ./run_lf.sh $lfexec
sleep 1

sudo ip netns exec eh0ns ping -c2 10.248.2.1
ping_success=$?

popd > /dev/null

# print ping result and exit with the same value
echo RESULTS.............
echo Ping Exit: $ping_success
exit $ping_success