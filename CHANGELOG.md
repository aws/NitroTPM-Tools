# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-11-17

### nitro-tpm-attest 2.0.0

#### Added
- `AttestationRequest` builder
- Owner authorization value, through `AttestationRequest::owner_auth` and `--owner-auth <file>`
- Exit code 75 when the TPM device is busy, the TPM has too little NV memory, or the TPM keeps answering that a command is retryable, see `Error::is_temporarily_unavailable`
- `--version`

#### Changed
- The kernel resource manager is required and is selected with `TPM_RESOURCE_MANAGER_DEVICE` (default `/dev/tpmrm0`); `TPM_DEVICE` only selects the device the vendor command falls back to on kernels before 6.3
- Several attestations can run at the same time on kernels 6.3 and later
- Attestations are faster: they authorize with password sessions instead of sessions salted to an endorsement key
- `Error` is non-exhaustive and its public API names no error types of dependencies, except the re-exported `nsm_api`; the `raw`, `tpm_manager` and `tss` modules are removed from the public API
- A TPM whose NV indices cannot hold an attestation document is rejected before the request with `Error::NvIndexSizeInsufficient`, instead of failing with a TPM error
- An attestation parameter larger than 1 KiB is rejected when it is set, with `Error::ParameterTooLarge`
- The command-line tool names the file it could not read, or the write to standard output that failed
- Updated dependencies

#### Fixed
- A request that fails while writing to its NV index tries to undefine it, instead of leaving it defined
- A failure to write the end of the attestation document to standard output no longer exits 0 with a truncated document
- The vendor command is submitted up to 5 times while the TPM answers that it is retryable, as the TSS does, instead of failing on the first retryable answer that reaches it
- The build script no longer panics when docs.rs builds the documentation

### nitro-tpm-pcr-compute 1.2.0

#### Added
- `--version`

#### Changed
- Updated dependencies

#### Fixed
- With `--PK`, a signature database of several lists no longer yields a wrong PCR7 or a parse failure
- PCR4 no longer measures the kernel of a unified kernel image started by a systemd-stub before version 252, which the firmware does not measure either
- An unreadable PK, KEK, db or dbx file is named in the error
- A failure to write the measurements is reported instead of panicking

## [1.1.2] - 2026-05-22

### nitro-tpm-pcr-compute 1.1.2

#### Changed
- Updated dependencies

### nitro-tpm-attest 1.0.3

#### Changed
- Updated dependencies

## [1.1.1] - 2026-04-10

### nitro-tpm-pcr-compute 1.1.1

#### Changed
- Updated dependencies

### nitro-tpm-attest 1.0.2

#### Changed
- Updated dependencies
- Updated to Rust 1.93

## [1.1.0] - 2025-12-08

### nitro-tpm-pcr-compute 1.1.0

#### Added
- PCR12 support with static zero value for detecting cmdline modifications

#### Changed
- Updated dependencies

### nitro-tpm-attest 1.0.1

#### Changed
- Updated dependencies

## [1.0.0] - 2025-10-22

Initial release of NitroTPM Tools.

### nitro-tpm-pcr-compute 1.0.0
- Precompute NitroTPM PCR 4 and 7 values based on Unified Kernel Images (UKI)
- Support for PE/COFF images in standard boot and UEFI Secure Boot environments

### nitro-tpm-attest 1.0.0
- Retrieve signed attestation documents from NitroTPM
