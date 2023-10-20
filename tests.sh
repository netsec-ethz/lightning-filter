#!/bin/bash

set -Euo pipefail

# Check that SCION_DIR is set.
# The SCION source directory points to the SCION repository
# including the SCION binaries in bin/.
if [ -z "$SCION_DIR" ]; then
    echo The SCION_DIR environment variable is not set!
    exit -1
fi

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

cmake_args="-D LF_WORKER=IPV4 -D LF_DRKEY_FETCHER=MOCK -D CMAKE_BUILD_TYPE=Release"
build_test
if [ $? -eq 0 ]
then
    run_integration_test test/testnet_ip/integration_test.sh $LF_EXEC
fi

cmake_args="-D LF_WORKER=FWD -D LF_DRKEY_FETCHER=MOCK -D LF_DISTRIBUTOR=ON"
build_test
if [ $? -eq 0 ]
then
    # Disable Ratelimiter in the integration test
    export LF_IT_NO_RL=1
    run_integration_test test/testnet_ip/integration_test.sh $LF_EXEC
    unset LF_IT_NO_RL
fi

cmake_args="-D LF_WORKER=IPV4 -D LF_DRKEY_FETCHER=MOCK -D LF_PLUGINS=\"bypass:dst_ratelimiter:wg_ratelimiter\""
build_test

cmake_args="-D LF_WORKER=SCION -D LF_DRKEY_FETCHER=SCION  -D CMAKE_BUILD_TYPE=Release"
build_test
if [ $? -eq 0 ]
then
    run_integration_test test/testnet_scion/integration_test.sh $LF_EXEC $SCION_DIR
fi

cmake_args="-D LF_WORKER=SCION -D LF_DRKEY_FETCHER=SCION -D LF_CBCMAC=AESNI -D CMAKE_BUILD_TYPE=Release"
build_test
if [ $? -eq 0 ]
then
    run_integration_test test/testnet_scion/integration_test.sh $LF_EXEC $SCION_DIR
fi

echo "Successful: $successful, Errors: $error"

exit $error

popd > /dev/null
