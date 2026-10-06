# NitroTPM Tools

A collection of utilities for working with NitroTPM attestation.

## Tools

- `nitro-tpm-attest`: A utility for requesting attestation documents from NitroTPM
- `nitro-tpm-pcr-compute`: A utility for precomputing PCR values of UKIs

For more information about each tool, see the respective README files.

## Static Builds

For static linking requirements, a Docker-based build environment is provided that can be used to statically link the TPM2 Software Stack (TSS2) and other dependencies.

```console
docker build --file docker/builder.Dockerfile --tag nitro-tpm-tools-builder .
docker run --rm --tty --volume cargo-cache:/root/.cargo/registry --volume "$PWD:/mnt" nitro-tpm-tools-builder cargo build --bins --release
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

NitroTPM Tools is licensed under the Apache 2.0 License (LICENSES/APACHEv2-LICENSE),
with the exception of the examples provided in nitro-tpm-attest/examples, which are
licensed under the MIT-0 License (LICENSES/MIT0-LICENSE).