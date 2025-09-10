FROM --platform=$TARGETPLATFORM rust:1.90-alpine3.22

RUN apk add --no-cache \
    build-base \
    curl \
    pkgconf \
    linux-headers \
    openssl-dev \
    openssl-libs-static

WORKDIR /tmp
ARG TPM2_TSS_VERSION=4.1.3
RUN curl --location "https://github.com/tpm2-software/tpm2-tss/releases/download/${TPM2_TSS_VERSION}/tpm2-tss-${TPM2_TSS_VERSION}.tar.gz" --output tpm2-tss-${TPM2_TSS_VERSION}.tar.gz
RUN tar xz --file tpm2-tss-${TPM2_TSS_VERSION}.tar.gz
RUN rm tpm2-tss-${TPM2_TSS_VERSION}.tar.gz

WORKDIR /tmp/tpm2-tss-${TPM2_TSS_VERSION}
RUN ./configure \
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
    --disable-tcti-null \
    --disable-tcti-libtpms \
    --disable-tcti-cmd \
    --disable-tcti-spi-helper \
    --disable-tcti-spi-lt2go \
    --disable-tcti-spi-spidev \
    --disable-tcti-spi-ftdi \
    --disable-tcti-i2c-helper \
    --disable-tcti-i2c-ftdi \
    --disable-weakcrypto \
    --disable-doxygen-doc
RUN make --jobs $(nproc)
RUN make install

WORKDIR /tmp
RUN rm -r tpm2-tss-${TPM2_TSS_VERSION}

WORKDIR /mnt
ENV PKG_CONFIG_ALL_STATIC 1
