# Lightning Filter Base Image
# Container for building and running the Lightning Filter
# Contains the necessary dependencies to build and run the Lightning Filter
#
# DPDK Version 23.11
# Go Version 1.21.2
# SCION Version 0.9.1

FROM ubuntu:jammy AS lf-base

# Packages for building
RUN apt-get update && \
    apt-get install -y sudo bash \
    git curl build-essential gcc make cmake pkg-config \
    libssl-dev yasm bsdmainutils tmux \
    meson ninja-build python3-pyelftools libnuma-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Golang
RUN curl -LO https://golang.org/dl/go1.21.2.linux-amd64.tar.gz && \
    echo "f5414a770e5e11c6e9674d4cd4dd1f4f630e176d1828d3427ea8ca4211eee90d go1.21.2.linux-amd64.tar.gz" | sha256sum -c && \
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.2.linux-amd64.tar.gz
ENV PATH /usr/local/go/bin:$PATH

# Install DPDK
RUN curl -LO https://fast.dpdk.org/rel/dpdk-23.11.tar.xz && \
echo "896c09f5b45b452bd77287994650b916 dpdk-23.11.tar.xz" | md5sum -c && \
tar xJf dpdk-23.11.tar.xz && cd dpdk-23.11 && \
    meson setup build && cd build && \
    if [ "$CI" = "true" ] ; then meson configure -Dmachine=default && meson compile; fi && \
    ninja && meson install && ldconfig
