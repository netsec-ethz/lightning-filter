# Installation

We recommended using Ubuntu 22.04 to duild (as well as develope and run) LightningFilter.
This sections presents the build setup. Also a docker container can be used for that (see [Docker](#Docker)).

## Dependencies
Some of the significant dependencies with specific versions required:
- DPDK 21.11 (see [DPDK.md](DPDK.md))
- OpenSSL Version >= 3.0
- CMake >= 3.20

To quickly install all required dependencies, run the script `usertools/install_deps.sh`.
> The script works for Ubuntu 22.04 on a x86 architecture.

The script installs required libraries and tools with apt.
DPDK and Golang are downloaded and built in the directory `dependencies` created in the current working directory.
Environment variables needed for building LightningFilter are defined in `depenedencies/env_vars`.

To set the environment variables, call `source dependencies/env_vars`.

To unset the environment variables, call `deactivate`.

## Build

To build LightningFilter we use CMake.
```
mkdir build
cd build
cmake ../
make
```

Note that DPDK is linked using pkg-config.
If you have not installed DPDK system-wide, set the environment variable `PKG_CONFIG_PATH` to include the required files.
E.g., if DPDK's install directory is `~/dpdk-21.11-inst`:
```
PKG_CONFIG_PATH=~/dpdk-21.11-inst/lib/x86_64-linux-gnu/pkgconfig/ cmake ../
```

### CMake Variables and Options

The build system offers multiple offers exposed through CMake variables, that are cached and can be changed individually.
Run `cmake -L` or `cmake -LH` to list all variables and their description.
The following presents an incomplete list:
```
LF_WORKER={SCION,IPV4,FWD}
LF_DRKEY_FETCHER={SCION,MOCK}
LF_LOG_DP_LEVEL={MIN,MAX,EMERG,ALERT,CRIT,ERR,WARNING,NOTICE,INFO,DEBUG}
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
git clone https://gitlab.inf.ethz.ch/OU-PERRIG/lightning-filter/lightning-filter.git
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

With the docker build, all dependencies are installed in the image and the build is performed in the container. See the script `docker.sh`.
To set specific compiler flags, we recommend starting a shell in the container.
