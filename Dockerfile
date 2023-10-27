# LF Builder image
# Container for building
FROM ubuntu:jammy AS lf-builder
ARG UID=1001
ARG GID=1001
ARG USER=lf

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
RUN curl -LO https://fast.dpdk.org/rel/dpdk-21.11.tar.xz && \
    echo "58660bbbe9e95abce86e47692b196555 dpdk-21.11.tar.xz" | md5sum -c && \
    tar xJf dpdk-21.11.tar.xz && cd dpdk-21.11 && \
    meson build && cd build && ninja && ninja install

# Allow the lf-build user to use sudo without a password
RUN groupadd --gid $GID --non-unique $USER && \
    useradd $USER --create-home --shell /bin/bash --non-unique --uid $UID --gid $GID && \
    echo "$USER ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set the default user for the container
USER $USER
ENV USER $USER
# Set the working directory for the user
WORKDIR /home/$USER

# LF Developer Image
# Container for developing (building, linting, testing)
FROM lf-builder AS lf-developer

# Add packages for developing, linting, and testing
RUN sudo apt-get update && \
    sudo apt-get install -y \
    bash-completion \
    clang-tidy clang-format iproute2 iputils-ping \
    python3-pip supervisor net-tools && \
    sudo rm -rf /var/lib/apt/lists/* && \
    sudo pip3 install plumbum toml supervisor-wildcards

# Require SCION NetSec binaries (contain DRKey) for SCION tests.
RUN git clone https://github.com/scionproto/scion.git && cd scion && \
    go build -o ./bin/ ./control/cmd/control && \
    go build -o ./bin/ ./daemon/cmd/daemon && \
    go build -o ./bin/ ./dispatcher/cmd/dispatcher && \
    go build -o ./bin/ ./router/cmd/router && \
    go build -o ./bin/ ./scion/cmd/scion && \
    go build -o ./bin/ ./scion-pki/cmd/scion-pki
ENV SCION_DIR=/home/$USER/scion
ENV SCION_BIN=/home/$USER/scion/bin

# Set the working directory for the user
WORKDIR /home/$USER
USER $USER
ENV USER $USER
