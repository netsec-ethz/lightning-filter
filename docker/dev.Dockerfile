
# Lightning Filter Developer Image
# Container for developing (building, linting, testing)
#
# Requires the base image as argument

FROM streun/lightning-filter:lf-base-v0.1.0 AS lf-dev
ARG UID=1001
ARG GID=1001
ARG USER=lf

# Allow the lf-build user to use sudo without a password
RUN groupadd --gid $GID --non-unique $USER && \
    useradd $USER --create-home --shell /bin/bash --non-unique --uid $UID --gid $GID && \
    echo "$USER ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set the default user for the container
USER $USER
ENV USER $USER
# Set the working directory for the user
WORKDIR /home/$USER

# Add packages for developing, linting, and testing
RUN sudo apt-get update && \
    sudo apt-get install -y \
    bash-completion \
    clang-tidy clang-format iproute2 iputils-ping \
    python3-pip supervisor net-tools && \
    sudo rm -rf /var/lib/apt/lists/* && \
    sudo pip3 install plumbum toml supervisor-wildcards

# Require SCION binaries for SCION tests.
RUN git clone https://github.com/scionproto/scion.git && \
    cd scion && \
    git checkout v0.9.1 && \
    go build -o ./bin/ ./control/cmd/control && \
    go build -o ./bin/ ./daemon/cmd/daemon && \
    go build -o ./bin/ ./dispatcher/cmd/dispatcher && \
    go build -o ./bin/ ./router/cmd/router && \
    go build -o ./bin/ ./scion/cmd/scion && \
    go build -o ./bin/ ./scion-pki/cmd/scion-pki
ENV SCION_DIR=/home/$USER/scion
ENV SCION_BIN=/home/$USER/scion/bin
