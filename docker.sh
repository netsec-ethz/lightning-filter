#!/bin/bash

set -x

CONTAINER_USER=lf
BUILD_CONTAINER=lf-container
DEV_CONTAINER=lf-dev-container

cmd_build () {
    CMAKE_ARGS="$@"
    cmd_build_image
    cmd_create
    cmd_up
    docker exec lf-container bash -c "mkdir build -p && cd build && cmake ../ $CMAKE_ARGS"
    docker exec lf-container bash -c "cd build && make"
    cmd_down
}

cmd_image () {
    docker build --target lf-builder -t lf-builder --build-arg UID=$(id -u) --build-arg GID=$(id -g) --build-arg USER="$CONTAINER_USER" .
}

cmd_create () {
    docker create --name lf-container --privileged --net=host \
    -v $PWD:/home/$CONTAINER_USER/lightning-filter/ \
    -v /dev/hugepages:/dev/hugepages -v /sys/bus/pci/devices:/sys/bus/pci/devices \
    lf-builder
}

cmd_up () {
    docker start lf-container

    # Add lightning-filter repo to the git safety exceptions
    docker exec lf-container git config --global --add safe.directory /home/$CONTAINER_USER/lightning-filter
}

cmd_down () {
    docker stop lf-container
}

cmd_shell () {
    docker exec -it lf-container bash
}

cmd_test () {
    cmd_dev_image
    cmd_dev_up
    cmd_down
}

cmd_dev_image () {
    docker build --target lf-developer -t lf-developer --build-arg UID=$(id -u) --build-arg GID=$(id -g) --build-arg USER="$CONTAINER_USER" .
}

cmd_dev_create () {
    docker create --name lf-dev-container --privileged --net=host \
    -v $PWD:/home/$CONTAINER_USER/lightning-filter/ \
    -v /dev/hugepages:/dev/hugepages -v /sys/bus/pci/devices:/sys/bus/pci/devices \
    lf-developer
}

cmd_dev_up () {
    docker container start lf-dev-container

    # Add lightning-filter repo to the git safety exceptions
    #docker exec lf-dev-container git config --global --add safe.directory /home/$CONTAINER_USER/lightning-filter
}

cmd_dev_down () {
    docker stop lf-dev-container
}

cmd_dev_exec () {
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
    help|build|image|create|up|down|shell|dev_image|dev_create|dev_up|dev_down|dev_exec)
        "cmd_$COMMAND" "$@" ;;
    *)  cmd_help; exit 1 ;;
esac
