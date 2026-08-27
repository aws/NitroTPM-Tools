// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The crate's error types

use crate::{nsm_api, raw, tss};

/// Failure of an attestation request
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// The NSM answered the attestation request with an invalid response
    #[error("invalid NSM response")]
    InvalidNsmResponse,
    /// The NSM answered with an error
    #[error("NSM error response: {0:?}")]
    NsmErrorResponse(nsm_api::ErrorCode),
    /// A TPM transport could not be opened
    #[error(transparent)]
    Open(#[from] OpenError),
    /// A failure of the TPM or of a library the crate builds on, kept opaque
    #[error(transparent)]
    Other(OtherError),
}

impl From<tss::message_buffer::Error> for Error {
    fn from(error: tss::message_buffer::Error) -> Self {
        Self::Other(OtherError(OtherErrorKind::MessageBuffer(error)))
    }
}

impl From<raw::Error> for Error {
    fn from(error: raw::Error) -> Self {
        Self::Other(OtherError(OtherErrorKind::NsmRequest(error)))
    }
}

impl Error {
    /// Whether the resource manager rejected the vendor command as unsupported, without the TPM
    /// seeing it
    pub(crate) fn is_unsupported_command(&self) -> bool {
        // The kernel answers a command it does not carry with TPM2_RC_COMMAND_CODE in the layer of
        // its resource manager, which tss2_common.h numbers 11
        const RESOURCE_MANAGER_COMMAND_CODE: tss_esapi::tss2_esys::TSS2_RC =
            tss_esapi::constants::tss::TPM2_RC_COMMAND_CODE
                | (11 << tss_esapi::tss2_esys::TSS2_RC_LAYER_SHIFT);

        let Self::Other(OtherError(OtherErrorKind::NsmRequest(raw::Error::TpmErrorResponse(
            tss_esapi::constants::response_code::Tss2ResponseCode::FormatZero(response_code),
        )))) = self
        else {
            return false;
        };

        response_code.0 == RESOURCE_MANAGER_COMMAND_CODE
    }
}

/// Failure of opening a TPM transport, naming the device it was opened on
#[derive(thiserror::Error, Debug)]
#[error("could not open the TPM device {device_path:?}")]
pub struct OpenError {
    pub(crate) device_path: std::path::PathBuf,
    pub(crate) source: OpenErrorKind,
}

impl OpenError {
    /// Path of the TPM device that could not be opened
    #[must_use]
    pub fn device_path(&self) -> &std::path::Path {
        &self.device_path
    }
}

/// Reason a TPM transport could not be opened
#[derive(thiserror::Error, Debug)]
pub(crate) enum OpenErrorKind {
    #[error("the path is not valid Unicode, which the TSS requires")]
    NonUnicodePath,
    #[error(transparent)]
    Tpm(#[from] raw::Error),
    #[error(transparent)]
    Tss(#[from] tss_esapi::Error),
}

/// Failure of one of the subsystems the crate builds on, kept opaque so their error types stay out
/// of the public interface
///
/// The message and source chain are preserved, so the underlying failure is still legible; only its
/// concrete type is hidden.
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct OtherError(OtherErrorKind);

/// The subsystem that failed
#[derive(thiserror::Error, Debug)]
enum OtherErrorKind {
    #[error(transparent)]
    MessageBuffer(tss::message_buffer::Error),
    #[error(transparent)]
    NsmRequest(raw::Error),
}
