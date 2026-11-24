# Cross toolchain for building Rust for aarch64-unknown-linux-gnu on an
# x86_64 runner, against glibc 2.17 so the result runs on any 64-bit
# Raspberry Pi OS (and most other ARM64 Linux). It follows upstream's
# host-x86_64/dist-armv7-linux image; build-aarch64-linux.sh assembles the
# context from the checkout's src/ci/docker/scripts plus the defconfig here.
FROM ubuntu:22.04

COPY scripts/cross-apt-packages.sh /scripts/
RUN sh /scripts/cross-apt-packages.sh

COPY scripts/crosstool-ng.sh /scripts/
COPY scripts/crosstool-ng-sha256-*.diff /scripts/
RUN sh /scripts/crosstool-ng.sh

COPY scripts/rustbuild-setup.sh /scripts/
RUN sh /scripts/rustbuild-setup.sh
WORKDIR /tmp

COPY scripts/crosstool-ng-build.sh /scripts/
COPY aarch64-linux-gnu.defconfig /tmp/crosstool.defconfig
RUN /scripts/crosstool-ng-build.sh

ENV PATH=$PATH:/x-tools/aarch64-unknown-linux-gnu/bin
ENV CC_aarch64_unknown_linux_gnu=aarch64-unknown-linux-gnu-gcc \
    AR_aarch64_unknown_linux_gnu=aarch64-unknown-linux-gnu-ar \
    CXX_aarch64_unknown_linux_gnu=aarch64-unknown-linux-gnu-g++ \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-unknown-linux-gnu-gcc \
    QEMU_LD_PREFIX=/x-tools/aarch64-unknown-linux-gnu/aarch64-unknown-linux-gnu/sysroot
