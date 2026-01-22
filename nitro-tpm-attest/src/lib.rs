// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Abstraction for the TPM2 AWS NSM Vendor Command
//!
//! Provides a high-level interface for the TPM2 AWS vendor command that is used to send NSM
//! attestation requests.

pub mod raw;
pub mod tpm_manager;
pub mod tss;

pub use aws_nitro_enclaves_nsm_api::api as nsm_api;
use tpm_manager::TpmManager;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid NSM response")]
    InvalidNsmResponse,
    #[error("NSM error response: {0:?}")]
    NsmErrorResponse(nsm_api::ErrorCode),
    #[error(transparent)]
    EndorsementKey(#[from] tss::endorsement_key::Error),
    #[error(transparent)]
    MessageBuffer(#[from] tss::message_buffer::Error),
    #[error(transparent)]
    NsmRequest(#[from] raw::nsm_request::Error),
    #[error(transparent)]
    Tss(#[from] tss_esapi::Error),
}

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

    let tpm_device_path =
        std::path::PathBuf::from(std::env::var_os("TPM_DEVICE").unwrap_or("/dev/tpm0".into()));
    let tpm_manager = std::cell::RefCell::new(TpmManager::new(tpm_device_path));

    let endorsement_key = tss::EndorsementKey::new(&tpm_manager)?;
    let (message_buffer, message_buffer_name) =
        tss::MessageBuffer::from_request(&tpm_manager, endorsement_key.tpm_handle(), &nsm_request)?;

    raw::nsm_request(
        &tpm_manager,
        endorsement_key.tpm_handle(),
        &endorsement_key.public_encryption_key()?,
        message_buffer.index(),
        message_buffer.auth(),
        &message_buffer_name,
    )?;

    match message_buffer.into_response()? {
        nsm_api::Response::Attestation { document } => Ok(document),
        nsm_api::Response::Error(error_code) => Err(Error::NsmErrorResponse(error_code)),
        _ => Err(Error::InvalidNsmResponse),
    }
}
