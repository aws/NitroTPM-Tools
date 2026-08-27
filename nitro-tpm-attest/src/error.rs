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
    /// A failure of the TPM or of a library the crate builds on, kept opaque
    #[error(transparent)]
    Other(OtherError),
}

impl From<tss::message_buffer::Error> for Error {
    fn from(error: tss::message_buffer::Error) -> Self {
        Self::Other(OtherError(OtherErrorKind::MessageBuffer(error)))
    }
}

impl From<raw::nsm_request::Error> for Error {
    fn from(error: raw::nsm_request::Error) -> Self {
        Self::Other(OtherError(OtherErrorKind::NsmRequest(error)))
    }
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
    NsmRequest(raw::nsm_request::Error),
}
