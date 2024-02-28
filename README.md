# LightningFilter (Open Source)

LightningFilter is a high-speed traffic filtering mechanism that performs authentication, rate limiting, and duplicate detection.
LightningFilter uses the DPDK framework, enabling high-speed packet processing.

This repository contains the open-source version, which offers at least the core functionalities of a LightningFilter.
The closed-source version provides additional functionalities.

## License

The software is licensed under BSD-3.

> The license might change to Apache v2 if possible.

### 3rd Party

DPDK (BSD 3) https://www.dpdk.org/

json-parser (BSD 2) https://github.com/json-parser/json-parser

murmurhash (public domain) https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp

hashdict (MIT licensed) https://github.com/exebook/hashdict.c

# Installation

See [docs/Installation.md](docs/Installation.md) for detailed information.

There are mainly two possibilities to build LightingFilter: with the help of a docker container or natively on a machine.
Both of the options rely on Ubuntu 22.04.

## Native

To install dependencies, we use the script provided in `usertools` and then set the required environment variables:

```
./usertools/install_deps.sh
source dependencies/env_vars
```

To build LightningFilter we use CMake.
```
mkdir build
cd build
cmake ../
make
```

## Docker Container

For the docker container build, install docker and add the user to the docker group.
Then run the `docker.sh` script to create the docker image and container that builds LightningFilter.

```
./docker.sh build <CMAKE_ARGS>
```

> Note: Because CMake flags are cached, once set, any following build call uses them.

# Run

After compiling the application, the executable is in `build/src/` and can be run as follows:

```
build/src/lf <EAL Parameters> -- <LF Parameters>
```

LightningFilter expects various parameters, which are divided into EAL and LF parameters.
Script examples that run LightningFilter can be found in the test directory, e.g., in [test/perfnet_ip](test/perfnet_ip).

DPDK defines the EAL parameters, which are described [here](https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html).
The application's help text describes the LF parameters.

E.g.:

```
build/src/lf --lcores (0-2)@(0-2),(3-7)@(3,7) --log-level lf:debug \
-- \
-p 0x1 --portmap "(0,0,o),(0,0,i)" --c lf_config.json
```

More info: [docs/Parameters.md](docs/Parameters.md)

## Statistics

The DPDK telemetry API provides information and statistics of a running DPDK instance.
Also, LightningFilter collects additional statistics and exposes them to the same interface.

Launch interactive client script:

```
sudo ./usertools/lf-telemetry.py
```

When using a file prefix, the file prefix is set with the -f flag:

```
sudo ./usertools/lf-telemetry.py -f "file_prefix"
```

More info: [docs/Metrics.md](docs/Metrics.md)

## Runtime Interface

LightningFilter provides an interface through a Unix socket during runtime, just as for the statistics.

Launch interactive client script:

```
sudo ./usertools/lf-ipc.py
```

When running LightningFilter with a file prefix, set the file prefix as follows:

```
sudo ./usertools/lf-ipc.py -f "file_prefix"
```

The script also allows running single commands without starting the interactive mode:

```
sudo ./usertools/lf-ipc.py --cmd=<command> {--params=<parameters>}
```

# Develop

To develop on LightningFilter, fork the repository, and clone it onto your machine. If you want to contribute to the open-source repository, we recommend adding the open-source repository as the upstream for the main branch (`open-source`):

```
git checkout open-source
git remote add upstream git@github.com:netsec-ethz/lightning-filter.git
git fetch upstream
git branch --set-upstream-to upstream/open-source
git pull
```

To get quickly started with developing LightningFilter, we provide a Development Container setup (`.devcontainer/devcontainer.json`) with all required dependencies and some useful tools.
When using VS Code, just install the [Visual Studio Code Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension and open the project in a container (`>Dev Container: Reopen in Container`).

Alternatively, the developer container can also be created with the `docker.sh` script:

```
./docker.sh dev_image && ./docker.sh dev_up
```

# Tests

## Unit Tests

(in the build directory)

```
make run_tests
```

> The tests require additional packages:
>```
>sudo apt-get install bsdmainutils tmux
>```

## Integration Tests
### SCION

(in `test/testnet_scion`)

```
sudo ./integration_test.sh ../../build/src/lf ~/scion
```

> Requires an appropriate build (see README in directory).

### IP

(in `test/testnet_ip`)

```
sudo ./integration_test.sh ../../build/src/lf
```

> Requires an appropriate build (see README in directory).

## Test Script

To run all of the unit and integration tests with different settings (compilation configurations), run the script `tests.sh`.

## Performance Tests

For the performance tests, use the test configurations in the directories `test/perfnet_scion` and `test/perfnet_ip`.
The `README.md`, in the corresponding directories, provides additional information on the setup and required adjustments.

# Documentation

The `docs` directory contains a collection of documentation files. The following list provides an overview of them.

- [Installation](docs/Installation.md)
    Description of the installation process and provider scripts.
    - [DPDK](docs/DPDK.md)
        Installation of DPDK (required by LightningFilter).
    - [SCION](docs/deployment/Deployment_SCION.md)
        Installation of a SCION setup (especially used for testing).

- [Functionality](docs/Functionalities.md)
    Description of the core functionalities
    - [Parameters](docs/Parameters.md)
    Documentation on the application parameters.
    - [Configuration](docs/Config.md)
    Documentation of configuration file.
    - [Metrics](docs/Metrics.md)
        - [Monitoring](docs/monitoring/Monitoring.md)
        Monitoring setup with Grafana
    - [IPC](docs/ipc/IPC.md)
    Inter process communication interface
    - [Features](docs/Features.md)
    Additional features (Jumbo Frames, Checksum Offloading)
    - [Plugins](docs/Plugins.md)
    Short description of the plugin system.
    -[Control Traffic](docs/control_traffic/Control_Traffic.md)
    Overview of control traffic processing

- Implementation
    - [Key Manager](docs/implementation/Keymanager.md)
    Overview of the keymanager module.
    - [Ratelimiter](docs/implementation/Ratelimiter.md)
    Overview of the ratelimiter module.
    - [Multi Core](docs/implementation/MultiCore.md)
    Multi core approach and distributor
    - [Code Quality](docs/implementation/Code_Quality.md)
    Code style and format, as well as linter
    - [Optimizations](docs/implementation/Optimizations.md)
    Optimization approaches and effects

- Specification
    - [SCION LF](docs/SCION&#32;LF.md)
    - [IP LF](docs/IP&#32;LF.md)

- Troubleshooting
    - [Debug](docs/troubleshooting/Debug.md)
    Debugging setup example (VSCode)
    - [Profiling](docs/troubleshooting/Profiling.md)
    Profiling setup example (Perf, VTune)
    - [Troubleshooting](docs/troubleshooting/Troubleshooting.md)
    Common problems and solutions

# Usertools

The directory `usertools` contains tools and scripts that allow the user to interact more easily with the LightningFilter.
