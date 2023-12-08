# LF Builder image
# Container for building
FROM ubuntu:jammy AS lf-builder
ARG UID=1001
ARG GID=1001
ARG USER=lf
ARG CI=false

# Packages for building
RUN apt-get update && \
    apt-get install -y sudo bash \
    git curl build-essential gcc make cmake pkg-config \
    libssl-dev yasm bsdmainutils tmux \
    meson ninja-build python3-pyelftools libnuma-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Golang
RUN curl -LO https://go.dev/dl/go1.17.9.linux-amd64.tar.gz && \
    echo "9dacf782028fdfc79120576c872dee488b81257b1c48e9032d122cfdb379cca6 go1.17.9.linux-amd64.tar.gz" | sha256sum -c && \
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.17.9.linux-amd64.tar.gz
ENV PATH /usr/local/go/bin:$PATH

# Install DPDK
RUN curl -LO https://fast.dpdk.org/rel/dpdk-23.11.tar.xz && \
    echo "896c09f5b45b452bd77287994650b916 dpdk-23.11.tar.xz" | md5sum -c && \
    tar xJf dpdk-23.11.tar.xz && cd dpdk-23.11 && \
    meson setup build && cd build && \
    if [ "$CI" = "true" ] ; then meson configure -Dmachine=default && meson compile; else echo "NO GITHUB ACTION $CI"; fi && \
    ninja && meson install && ldconfig

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
RUN git clone https://github.com/netsec-ethz/scion.git && cd scion && \
    go build -o ./bin/ ./go/cs/ && \
    go build -o ./bin/ ./go/posix-router/ && \
    go build -o ./bin/ ./go/dispatcher/ && \
    go build -o ./bin/ ./go/daemon/ && \
    go build -o ./bin/ ./go/scion-pki/ && \
    go build -o ./bin/ ./go/scion/
ENV SCION_DIR=/home/$USER/scion
ENV SCION_BIN=/home/$USER/scion/bin

# Set the working directory for the user
WORKDIR /home/$USER
USER $USER
ENV USER $USER
