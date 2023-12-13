# Installation

For building LightningFilter, we recommended our docker setup (see [Docker](#Docker)), which already provides all dependencies.

## Dependencies

Some of the significant dependencies with specific versions required:
- DPDK 23.11 (see [DPDK.md](DPDK.md))
- OpenSSL Version >= 3.0
- CMake >= 3.20

Alternatively, to the provided docker setup, you can install all dependencies with the script `usertools/install_deps.sh`.
DPDK and Golang are downloaded and built in the directory `dependencies` created in the current working directory.
Environment variables needed for building LightningFilter are defined in `depenedencies/env_vars`.

To set the environment variables, call `source dependencies/env_vars`.

To unset the environment variables, call `deactivate`.

> The script works for Ubuntu 22.04 on a x86 architecture.

## Build

To build LightningFilter we use CMake.

```
mkdir build
cd build
cmake ../
make
```

### CMake Variables and Options

The build system offers multiple options exposed through CMake variables.
Run `cmake -L` or `cmake -LH` to list all variables and their description.

The following presents an incomplete list:

```
LF_WORKER={SCION,IPV4,FWD}
LF_DRKEY_FETCHER={SCION,MOCK}
LF_LOG_DP_LEVEL={MIN,MAX,EMERG,ALERT,CRIT,ERR,WARNING,NOTICE,INFO,DEBUG}
LF_CBCMAC={OPENSSL,AESNI}
```

Set CMake variables as follows:

```
cmake ../ -D<variable>=<value>
```

## Example Build

Ubuntu 22.04

``` bash
sudo apt update
sudo apt -y install git

## Get LF source
git clone https://github.com/netsec-ethz/lightning-filter.git
pushd lightning-filter
git checkout fstreun/main_dev

## Install dependencies and write stdout and stderr to log file.
./usertools/install_deps.sh &> install_deps.log

## Set environmental variables
source dependencies/env_vars

## Prepare CMake build
mkdir build
pushd build
cmake ../

## Build LF
make

## Run (unit) tests
make run_tests
```

## Docker

With the docker build, all dependencies are installed in the image, and the build is performed in the container. See the script `docker.sh`.
