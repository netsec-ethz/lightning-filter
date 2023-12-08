# DPDK Installation, Configuration, and Usage

(Version 23.11)

## Installation

### Requirements

See [DPDK Requirement](http://doc.dpdk.org/guides/linux_gsg/sys_reqs.html) for information.

```
pip3 install --user meson ninja pyelftools
export PATH="~/.local/bin:$PATH"
```

> In some cases it is possible that meson does not find ninja when building the system.
A temporary solution is to install ninja with apt: `sudo apt install ninja-build`.

```
sudo apt install python3-pyelftools
sudo apt install libnuma-dev
```

### Compiling and Installing DPDK System-wide

Source: [Compiling the DPDK Target from Source](http://doc.dpdk.org/guides-23.11/linux_gsg/build_dpdk.html)

```
curl -LO https://fast.dpdk.org/rel/dpdk-23.11.tar.xz && \
echo "896c09f5b45b452bd77287994650b916 dpdk-23.11.tar.xz" | md5sum -c && \
tar xJf dpdk-23.11.tar.xz && cd dpdk-23.11 && \
meson setup build && cd build && ninja && meson install && ldconfig
```

#### Configure Build

DPDK uses meson to configure its build.

```
meson <options> <build directory>
```

E.g., to set the instal directory to `~/dpdk-23.11-inst`:

```
meson --prefix ~/dpdk-23.11-inst build
```

In the build directory, meson can further be used to adjust the build configurations:

```
meson configure -D<option>=<value>
```

Checkout ``meson configure`` to list the configuration options.

### Linux Drivers

https://doc.dpdk.org/guides/linux_gsg/linux_drivers.html
https://doc.dpdk.org/guides/tools/devbind.html

Network interfaces have to be bound to the correct driver.
E.g., the standard `uio_pci_generic` module included in the Linux kernel can be used.

```
sudo modprobe uio_pci_generic
```

As an alternative to the `uio_pci_generic`, there is the `igb_uio` module which can be found in the repository dpdk-kmods. It can be loaded as shown below:

```
sudo modprobe uio
sudo insmod igb_uio.ko
```

Install igb_uio.ko from dpdk-kmods and insert the module:

```
git clone https://dpdk.org/git/dpdk-kmods
cd dpdk-kmods/linux/igb_uio/
make
sudo modprobe uio
sudo insmod igb_uio.ko
```

The status of the interfaces can be checked as follows:

``` shell
dpdk-devbind.py -s
```

To bind an interface to the uio_pci_generic:

``` shell
dpdk-devbind.py -b uio_pci_generic 0000:00:08.0
```

### Hugepages

TODO

```
echo '4096' | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

### Mellanox

https://doc.dpdk.org/guides-21.11/nics/mlx5.html?highlight=mlnxofedinstall
(especially: Quick Start Guide on OFED/EN)

https://usermanual.wiki/m/6532977b8b83a8ab795b107ae033dd51cc1497de5afb0df677423e0aa8079459.pdf#%5B%7B%22num%22%3A27%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C707%2C0%5D

For Mellanox support, install OFED on the target host:

```
wget 'https://content.mellanox.com/ofed/MLNX_OFED-5.4-1.0.3.0/MLNX_OFED_LINUX-5.4-1.0.3.0-debian10.8-x86_64.iso' -O ./MLNX_OFED_LINUX-5.4-1.0.3.0-debian10.8-x86_64.iso
echo "01c8314eec0369830d7c2acea159726d43f8a480ac18f28b701de3d44b4753d0 MLNX_OFED_LINUX-5.4-1.0.3.0-debian10.8-x86_64.iso" | sha256sum -c MLNX_OFED_LINUX*
sudo mkdir /mnt/iso
sudo mount -o loop ./MLNX_OFED_LINUX-5.4-1.0.3.0-debian10.8-x86_64.iso /mnt/iso/
cd /mnt/iso/
sudo apt install libpython3.7
sudo ./mlnxofedinstall --upstream-libs --dpdk
/etc/init.d/openibd status
```

Potentially following dependencies also have to be installed:

```
sudo apt install rdma-core
```

## Troubleshooting

### Installation: Python Version

The meson installation scripts always choose the system's Python version and not the Python version globally configured, e.g., with `pyenv`. If the another version is preferred, adjust the build script `buildtools/meson.build` by changing the line

```
python3 = import('python').find_installation(required: false)
```

to

```
python3 = import('python').find_installation('python3', required: false)
```
