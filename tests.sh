#!/bin/bash

set -Euo pipefail

# Move to the script directory.
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
pushd $SCRIPT_DIR > /dev/null

# Check that SCION_DIR is set.
# The SCION source directory points to the SCION repository
# including the SCION binaries in bin/.
if [ -z "$SCION_DIR" ]; then
    echo The SCION_DIR environment variable is not set!
    exit -1
fi

# Create tmp directory and get absolute path to it.
TMP_DIR=tmp
mkdir -p $TMP_DIR
TMP_DIR=$(cd $TMP_DIR && pwd)


# Create build directory and get absolute path to it.
BUILD_DIR=$TMP_DIR/tests_build
mkdir -p $BUILD_DIR
BUILD_DIR=$(cd $BUILD_DIR && pwd)
# Get absolute path to the lf executable.
LF_EXEC=$BUILD_DIR/src/lf

# Create artifacts directory and get absolute path to it.
ARTIFACTS_DIR=$TMP_DIR/tests_artifacts
mkdir -p $ARTIFACTS_DIR
ARTIFACTS_DIR=$(cd $ARTIFACTS_DIR && pwd)

CURRENT_TIME=$(date "+%Y_%m_%d_%H_%M_%S")

function run_integration_test() {
    script=$1
    lf_exec=$2
    args="${@:3}"

    # LF logs should be stored in the artifacts directory.
    log_dir="${ARTIFACTS_DIR}/${CURRENT_TIME}_${test_label}/lf_logs"
    mkdir -p $log_dir
    export LF_LOG_DIR=$log_dir

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
    rm CMakeCache.txt

    if (
        cmake $SCRIPT_DIR $cmake_args
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

    # Copy build artifacts to artifact directory.
    artifacts_build_dir="${ARTIFACTS_DIR}/${CURRENT_TIME}_${test_label}/build"
    mkdir -p $artifacts_build_dir
    cp -r Testing/Temporary $artifacts_build_dir
    cp CMakeCache.txt "${artifacts_build_dir}/"

    popd > /dev/null

    return $ret
}

function make_artifacts_dir() {
    artifacts_dir="${ARTIFACTS_DIR}/${CURRENT_TIME}_${test_label}"
    mkdir -p $artifacts_dir
}

successful=0
error=0
cmake_args=""

test_label="lf_ipv4_drkey_mock"
make_artifacts_dir
cmake_args="-D LF_WORKER=IPV4 -D LF_DRKEY_FETCHER=MOCK -D CMAKE_BUILD_TYPE=Release"
build_test
if [ $? -eq 0 ]
then
    run_integration_test test/testnet_ip/integration_test.sh $LF_EXEC
fi

test_label="lf_fwd"
make_artifacts_dir
cmake_args="-D LF_WORKER=FWD -D LF_DRKEY_FETCHER=MOCK"
build_test
if [ $? -eq 0 ]
then
    # Disable Ratelimiter in the integration test
    export LF_IT_NO_RL=1
    run_integration_test test/testnet_ip/integration_test.sh $LF_EXEC
    unset LF_IT_NO_RL
fi

test_label="lf_fw_plugins"
make_artifacts_dir
cmake_args="-D LF_WORKER=IPV4 -D LF_DRKEY_FETCHER=MOCK -D LF_PLUGINS=\"bypass:dst_ratelimiter:wg_ratelimiter\""
build_test

test_label="lf_scion_drkey_scion"
make_artifacts_dir
cmake_args="-D LF_WORKER=SCION -D LF_DRKEY_FETCHER=SCION  -D CMAKE_BUILD_TYPE=Release"
build_test
if [ $? -eq 0 ]
then
    run_integration_test test/testnet_scion/integration_test.sh $LF_EXEC $SCION_DIR
fi

test_label="lf_scion_drkey_scion_aesni"
cmake_args="-D LF_WORKER=SCION -D LF_DRKEY_FETCHER=SCION -D LF_CBCMAC=AESNI -D CMAKE_BUILD_TYPE=Release"
build_test
if [ $? -eq 0 ]
then
    run_integration_test test/testnet_scion/integration_test.sh $LF_EXEC $SCION_DIR
fi

echo "Successful: $successful, Errors: $error"

exit $error

popd > /dev/null
