#!/usr/bin/env bash

set -Euo pipefail

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

pushd $SCRIPT_DIR > /dev/null

TMUX_SESSION="lf_session"

./scion/gen-topo.sh $scion_dir

./testnet.sh up
sleep 0.1
./scion/supervisor/supervisor.sh reload
./scion/supervisor/supervisor.sh start all
sleep 1

sudo tmux new-session -d -s $TMUX_SESSION ./run_lf.sh $lfexec
sleep 5

if (
	sudo ip netns exec far-0 $scion_dir/bin/scion ping -c 2 --sciond 10.248.3.1:30255 --dispatcher /run/shm/dispatcher/endhost1-ff00_0_111.sock 1-ff00:0:112,10.248.5.2
)
then
	ping_success=0
else
# try again
	sleep 1
	sudo ip netns exec far-0 $scion_dir/bin/scion ping -c 2 --sciond 10.248.3.1:30255 --dispatcher /run/shm/dispatcher/endhost1-ff00_0_111.sock 1-ff00:0:112,10.248.5.2
	ping_success=$?
fi

popd > /dev/null

echo RESULTS.............
echo Ping Exit: $ping_success

exit $ping_success