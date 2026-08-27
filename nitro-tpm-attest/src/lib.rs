// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Abstraction for the TPM2 AWS NSM Vendor Command
//!
//! Provides a high-level interface for the TPM2 AWS vendor command that is used to send NSM
//! attestation requests.
//!
//! The TSS and the vendor command both go through the kernel resource manager, which admits many
//! users at a time, so a concurrent invocation cannot take the TPM away mid-request. The resource
//! manager device is configurable through TPM_RESOURCE_MANAGER_DEVICE.

mod raw;
mod tss;

mod error;

pub use aws_nitro_enclaves_nsm_api::api as nsm_api;
pub use error::*;

/// Request a NitroTPM attestation document
pub fn attestation_document(
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    let nsm_request = nsm_api::Request::Attestation {
        user_data: user_data.map(Into::into),
        nonce: nonce.map(Into::into),
        public_key: public_key.map(Into::into),
    };

    let tpm_resource_manager_device_path = std::path::PathBuf::from(
        std::env::var_os("TPM_RESOURCE_MANAGER_DEVICE")
            // An empty variable would take the TSS to /dev/tpm0 and open nothing at all for the
            // vendor command, instead of both going through the resource manager
            .filter(|path| !path.is_empty())
            .unwrap_or_else(|| "/dev/tpmrm0".into()),
    );
    let mut context = tpm_resource_manager_device_path
        .to_str()
        .ok_or(OpenErrorKind::NonUnicodePath)
        .and_then(|path| {
            Ok(tss_esapi::Context::new(tss_esapi::TctiNameConf::Device(
                std::str::FromStr::from_str(path)?,
            ))?)
        })
        .map_err(|source| OpenError {
            device_path: tpm_resource_manager_device_path.clone(),
            source,
        })?;

    let message_buffer = tss::MessageBuffer::from_request(&mut context, &nsm_request)?;

    let mut tpm = raw::Tpm::new(&tpm_resource_manager_device_path).map_err(|error| OpenError {
        device_path: tpm_resource_manager_device_path.clone(),
        source: error.into(),
    })?;
    tpm.nsm_request(message_buffer.index(), message_buffer.auth())?;

    match message_buffer.into_response()? {
        nsm_api::Response::Attestation { document } => Ok(document),
        nsm_api::Response::Error(error_code) => Err(Error::NsmErrorResponse(error_code)),
        _ => Err(Error::InvalidNsmResponse),
    }
}
