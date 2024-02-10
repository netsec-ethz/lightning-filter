#!/bin/bash
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
pushd $SCRIPTPATH > /dev/null
cd ..

mkdir -p logs

# Wrap the 'supervisorctl' command
OPTIONS="$@"
CONF_FILE="supervisor/supervisord.conf"
if [ ! -e /tmp/supervisor.sock ]; then
    sudo supervisord -c $CONF_FILE
fi
sudo supervisorctl -c $CONF_FILE $OPTIONS

popd > /dev/null