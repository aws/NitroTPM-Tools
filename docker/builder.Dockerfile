FROM --platform=$TARGETPLATFORM rust:1.99-alpine3.24 AS base

RUN apk add --no-cache \
    build-base \
    curl \
    pkgconf \
    linux-headers \
    openssl-dev \
    openssl-libs-static

FROM base AS tpm2-tss-version
RUN apk add --no-cache jq
RUN --mount=type=bind,target=/src \
    cargo metadata --manifest-path /src/Cargo.toml --no-deps --format-version 1 \
    | jq --raw-output --exit-status '.metadata."tpm2-tss".version' \
    > /tpm2-tss-version

FROM base

WORKDIR /tmp
ARG TPM2_TSS_VERSION
RUN --mount=type=bind,from=tpm2-tss-version,source=/tpm2-tss-version,target=/tmp/tpm2-tss-version \
    version="${TPM2_TSS_VERSION:-$(cat tpm2-tss-version)}" \
    && curl --location --fail "https://github.com/tpm2-software/tpm2-tss/releases/download/${version}/tpm2-tss-${version}.tar.gz" --output tpm2-tss.tar.gz
RUN mkdir tpm2-tss && tar xz --file tpm2-tss.tar.gz --directory tpm2-tss --strip-components 1
RUN rm tpm2-tss.tar.gz

WORKDIR /tmp/tpm2-tss
RUN ./configure \
    --enable-option-checking=fatal \
    --prefix=/usr/local \
    --disable-shared \
    --enable-nodl \
    --disable-fapi \
    --disable-vendor \
    --disable-policy \
    --enable-tcti-device \
    --disable-tcti-mssim \
    --disable-tcti-swtpm \
    --disable-tcti-pcap \
    --disable-tcti-libtpms \
    --disable-tcti-cmd \
    --disable-tcti-spi-helper \
    --disable-tcti-spi-ftdi \
    --disable-tcti-i2c-helper \
    --disable-tcti-i2c-ftdi \
    --disable-weakcrypto \
    --disable-doxygen-doc
RUN make --jobs $(nproc)
RUN make install

WORKDIR /tmp
RUN rm -r tpm2-tss

WORKDIR /mnt
ENV PKG_CONFIG_ALL_STATIC 1
