#!/bin/bash

set -x

cmd_dev_create() {
    DEV_VERSION=$(cat dev.version)
    docker create --name lf-dev-container --privileged --net=host \
    -v $PWD/..:/home/lf/lightning-filter/ \
    -v /dev/hugepages:/dev/hugepages -v /sys/bus/pci/devices:/sys/bus/pci/devices \
    streun/lightning-filter:$DEV_VERSION sleep infinity
}

cmd_dev_up() {
    docker start lf-dev-container
}

cmd_dev_down() {
    docker stop lf-dev-container
}

cmd_dev_exec() {
    docker exec lf-dev-container "$@"
}

cmd_help() {
	echo
	cat <<-_EOF
	Usage:
	    $PROGRAM help
	        Show this text.
	_EOF
}

# END subcommand functions

PROGRAM="${0##*/}"
COMMAND="$1"
shift

case "$COMMAND" in
    help|dev_image|dev_create|dev_up|dev_down|dev_exec)
        "cmd_$COMMAND" "$@" ;;
    *)  cmd_help; exit 1 ;;
esac
