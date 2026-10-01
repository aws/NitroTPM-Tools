# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - Unreleased

### nitro-tpm-attest 2.0.0

#### Added
- `AttestationRequest` builder
- Owner authorization value, through `AttestationRequest::owner_auth` and `--owner-auth <file>`
- Exit code 75 when the TPM device is busy or the TPM is out of NV memory, see `Error::is_temporarily_unavailable`
- `--version`

#### Changed
- Several attestations can run at the same time on kernels 6.3 and later
- The kernel resource manager is required and is selected with `TPM_RESOURCE_MANAGER_DEVICE` (default `/dev/tpmrm0`); `TPM_DEVICE` only selects the device the vendor command falls back to on kernels before 6.3
- Attestations are faster: they authorize with password sessions instead of sessions salted to an endorsement key
- `Error` is non-exhaustive and no longer exposes the error types of dependencies, except the re-exported `nsm_api`; the `raw`, `tpm_manager` and `tss` modules are removed from the public API

#### Fixed
- A request that fails while being written to its NV index no longer leaves the index defined
- A failure to write the end of the attestation document to standard output no longer exits 0 with a truncated document

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
