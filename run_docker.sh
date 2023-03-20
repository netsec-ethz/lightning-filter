#!/bin/bash

set -x

USER=lf

cmd_build () {
    CMAKE_ARGS="$@"
    cmd_build_image
    cmd_up
    docker exec lf-container bash -c "mkdir build -p && cd build && cmake ../ $CMAKE_ARGS"
    docker exec lf-container bash -c "cd build && make"
    cmd_down
}

cmd_image () {
    docker build --target lf-builder -t lf-builder --build-arg UID=$(id -u) --build-arg GID=$(id -g) --build-arg USER="$USER" .
}

cmd_up () {
    docker run -it --name lf-container --privileged --net=host -d \
    -v $PWD:/home/$USER/lightning-filter/ \
    -v /dev/hugepages:/dev/hugepages -v /sys/bus/pci/devices:/sys/bus/pci/devices \
    lf-builder

    # Add lightning-filter repo to the git safety exceptions
    docker exec lf-container git config --global --add safe.directory /home/$USER/lightning-filter
}

cmd_down () {
    docker rm -f lf-container
}

cmd_shell () {
    docker exec -it lf-container bash
}

cmd_dev_image () {
    docker build --target lf-developer -t lf-developer --build-arg UID=$(id -u) --build-arg GID=$(id -g) --build-arg USER="$USER" .
}

cmd_dev_up () {
    docker run -it --name lf-dev-container --privileged --net=host -d \
    -v $PWD:/home/$USER/lightning-filter/ \
    -v /dev/hugepages:/dev/hugepages -v /sys/bus/pci/devices:/sys/bus/pci/devices \
    lf-developer

    # Add lightning-filter repo to the git safety exceptions
    docker exec lf-dev-container git config --global --add safe.directory /home/$USER/lightning-filter
}

cmd_dev_down () {
    docker rm -f lf-dev-container
}

cmd_dev_shell () {
    docker exec -it lf-dev-container bash
}

cmd_runner_image () {
    docker build --target lf-runner -t lf-runner --build-arg UID=$(id -u) --build-arg GID=$(id -g) --build-arg USER="$USER" .
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
    help|build|image|up|down|shell|dev_image|dev_up|dev_down|dev_shell|runner_image)
        "cmd_$COMMAND" "$@" ;;
    *)  cmd_help; exit 1 ;;
esac
