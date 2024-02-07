#!/bin/bash
####################################
# This is a quick dependency installation script
# that suited for Ubuntu 22.04 on a x86 architecture.
#
# Required libraries and tools are installed with apt.
# DPDK and Golang are downloaded and build in a folder
# called "dependencies" created in the current working directory.
#
# Environment variables required for building LightningFilter
# are defined in depenedencies/env_vars.
####################################
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
WORKING_DIR=$PWD
DEP_DIR=$WORKING_DIR/dependencies
ENV_VARS_FILE=$DEP_DIR/env_vars

mkdir $DEP_DIR

cp $SCRIPT_DIR/dependencies/env_vars_template $ENV_VARS_FILE
echo >> $ENV_VARS_FILE
echo "# The following lines were created by install_deps.sh" >> $ENV_VARS_FILE

#######################################
# General Dependencies
#######################################
# For building
sudo apt -y install build-essential gcc make cmake pkg-config
# OpenSSL
sudo apt -y install libssl-dev
# AESNI
sudo apt -y install yasm
# Testing Dependencies
sudo apt -y install bsdmainutils tmux

#######################################
# DPDK
#######################################
pushd $DEP_DIR
## Install required tools and libraries
sudo apt -y install build-essential meson ninja-build python3-pyelftools libnuma-dev
## Get source
curl -LO https://fast.dpdk.org/rel/dpdk-23.11.tar.xz
echo "896c09f5b45b452bd77287994650b916 dpdk-23.11.tar.xz" | md5sum -c
tar xJf dpdk-23.11.tar.xz
pushd dpdk-23.11
## Build and Install DPDK
meson --prefix $DEP_DIR/dpdk-23.11-inst build
pushd build
ninja
ninja install
# Add to pkg-config PATH
echo >> $ENV_VARS_FILE
echo "# set PKG_CONFIG_PATH so it includes DPDK pkg-config" >> $ENV_VARS_FILE
echo "export PKG_CONFIG_PATH=\$PKG_CONFIG_PATH:$DEP_DIR/dpdk-23.11-inst/lib/x86_64-linux-gnu/pkgconfig/" >> $ENV_VARS_FILE
## Return to working directory
popd && popd && popd

#######################################
# Golang
#######################################
pushd $DEP_DIR
# Get source
curl -LO https://golang.org/dl/go1.21.2.linux-amd64.tar.gz
echo "f5414a770e5e11c6e9674d4cd4dd1f4f630e176d1828d3427ea8ca4211eee90d go1.21.2.linux-amd64.tar.gz" | sha256sum -c
sudo tar -C $DEP_DIR -xzf go1.21.2.linux-amd64.tar.gz
# Add to PATH
echo >> $ENV_VARS_FILE
echo "# set PATH so it includes Go" >> $ENV_VARS_FILE
echo "export PATH=\$PATH:$DEP_DIR/go/bin" >> $ENV_VARS_FILE
## Return to working directory
popd

########################################
# GitHub Actions
########################################
# Set environmental variables for GitHub Actions
if [ -n "$GITHUB_ENV" ]; then
    echo "$DEP_DIR/go/bin" >> $GITHUB_PATH
    echo "PKG_CONFIG_PATH=$DEP_DIR/dpdk-23.11-inst/lib/x86_64-linux-gnu/pkgconfig/" >> $GITHUB_ENV
fi
