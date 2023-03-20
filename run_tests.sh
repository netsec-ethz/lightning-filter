#!/bin/bash

set -Euo pipefail

# SCION source directory with the SCION binaries in bin/.
SCION_DIR=$1

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

BUILD_DIR=build_test
LF_EXEC=$BUILD_DIR/src/lf

CURRENT_TIME=$(date "+%Y_%m_%d_%H_%M_%S")
counter=0

successful=0
error=0

pushd $SCRIPT_DIR > /dev/null

mkdir $BUILD_DIR

cmake_args=""

function run_integration_test() {
    script=$1
    lf_exec=$2
    args="${@:3}"

    if (
        $script $lf_exec $args
    )
    then
        let successful++
        echo "success" $successful
    else
        echo "error"
        let error++
    fi
}

function build_test() {
    pushd $BUILD_DIR > /dev/null
    mkdir -p Testing/History
    dir="Testing/History/${CURRENT_TIME}_${counter}"
    rm CMakeCache.txt

    if (
        cmake ../ $cmake_args
        make
        make run_tests
    )
    then
        let successful++
        echo "success" $successful
        ret=0
    else
        echo "error"
        let error++
        ret=1
    fi

    cp -r Testing/Temporary $dir
    cp CMakeCache.txt "${dir}/"

    let counter++
    popd > /dev/null

    return $ret
}

cmake_args="-D LF_WORKER=IPV4 -D LF_DRKEY_FETCHER=MOCK"
build_test
if [ $? -eq 0 ]
then
    run_integration_test test/testnet_ip/integration_test.sh $LF_EXEC
fi

cmake_args="-D LF_WORKER=IPV4 -D LF_DRKEY_FETCHER=MOCK -D LF_PLUGINS=\"dst_ratelimiter:wg_ratelimiter\""
build_test

cmake_args="-D LF_WORKER=SCION -D LF_DRKEY_FETCHER=SCION"
build_test
if [ $? -eq 0 ]
then
run_integration_test test/testnet_scion/integration_test.sh $LF_EXEC $SCION_DIR
fi

cmake_args="-D LF_WORKER=FWD -D LF_DRKEY_FETCHER=MOCK -D LF_DISTRIBUTOR=ON"
build_test


if [[ $error -eq 0 ]]; then
    echo "Successful: $successful, Errors: $error"
	exit 0
else
    echo "Successful: $successful, Errors: $error"
	exit 1
fi

popd > /dev/null