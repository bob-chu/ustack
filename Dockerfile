FROM ubuntu:24.04

# Install build-essential and network utilities
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    meson \
    ninja-build \
    libnuma-dev \
    libpci3 \
    tk \
    tcl \
    libmnl0 \
    automake \
    lsof \
    libnl-3-200 \
    chrpath \
    autotools-dev \
    autoconf \
    flex \
    kmod \
    ethtool \
    libelf1 \
    libnl-route-3-dev \
    gfortran \
    m4 \
    libnl-route-3-200 \
    pciutils \
    libnl-3-dev \
    libfuse2 \
    bison \
    libusb-1.0-0 \
    graphviz \
    debhelper \
    libltdl-dev \
    swig \
    pkg-config \
    udev \
    libgfortran5 \
    python3-pyelftools \
    libev-dev \
    libssl-dev \
    xz-utils \
    golang-go \
    git \
    iproute2 \
    netcat-traditional \
    tcpdump \
    gdb \
    && apt-get clean

ARG ZIG_VERSION=0.14.0

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
        amd64) zig_arch="x86_64" ;; \
        arm64) zig_arch="aarch64" ;; \
        *) echo "Unsupported architecture: ${arch}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${zig_arch}-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz; \
    tar -xJf /tmp/zig.tar.xz -C /opt; \
    ln -s "/opt/zig-linux-${zig_arch}-${ZIG_VERSION}/zig" /usr/local/bin/zig; \
    rm -f /tmp/zig.tar.xz

# Set the working directory inside the container
WORKDIR /app
