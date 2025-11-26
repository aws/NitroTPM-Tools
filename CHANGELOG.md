# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
