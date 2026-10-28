// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The crate's error types

use crate::{nsm_api, raw, tss};

/// Failure of an attestation request
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// The TPM cannot hold an NV index as large as an attestation may need
    #[error(
        "an attestation document takes up to {} bytes, but the TPM holds at most {available} \
         per NV index, so EC2 instance attestation is not supported on this TPM",
        tss::message_buffer::MAX_SIZE
    )]
    #[non_exhaustive]
    NvIndexSizeInsufficient {
        /// Size in bytes of the largest NV index the TPM holds
        available: usize,
    },
    /// An optional attestation parameter is larger than the NSM accepts
    #[error(
        "the {parameter} is larger than the {} bytes the NSM accepts",
        tss::message_buffer::PARAMETER_MAX_SIZE
    )]
    #[non_exhaustive]
    ParameterTooLarge {
        /// The parameter that is too large
        parameter: AttestationParameter,
    },
    /// The owner authorization value is longer than the TPM accepts
    #[error("the owner authorization value is longer than the TPM accepts")]
    OwnerAuthTooLong,
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
    /// Wraps a failure of the TSS into the opaque Other variant
    ///
    /// Unlike the other failures it has no From conversion, since the TSS error is public and a
    /// conversion from it would name the TSS in this interface.
    pub(crate) fn from_tss(error: tss_esapi::Error) -> Self {
        Self::Other(OtherError(OtherErrorKind::Tss(error)))
    }

    /// Whether a retry might fix the failure, as when the TPM had no NV memory left for the request
    /// or the TPM device was busy, most often because another attestation held them
    ///
    /// An attestation holds an NV index for its duration. Where the resource manager does not carry
    /// the vendor command, it also holds the TPM device while that command runs. A TPM has little
    /// NV memory to spare and the device admits a single user, so attestations running next to each
    /// other can run out of either. Retrying is left to the caller, which knows how long it can
    /// afford to wait, but it takes this to tell such a failure apart from any other.
    #[must_use]
    pub fn is_temporarily_unavailable(&self) -> bool {
        // Only the TPM device admits a single user, so only there does busy mean another
        // attestation holds it
        if let Self::Open(OpenError {
            transport: Transport::Device,
            source: OpenErrorKind::Tpm(raw::Error::Io(error)),
            ..
        }) = self
        {
            return error.kind() == std::io::ErrorKind::ResourceBusy;
        }

        self.response_code_kind()
            == Some(tss_esapi::constants::response_code::Tss2ResponseCodeKind::NvSpace)
    }

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

    /// The kind of the TPM response code of a failed TSS command, or none for any other error
    ///
    /// The reads and writes of the message buffer report their failures as I/O errors, so their
    /// response codes are not seen here.
    fn response_code_kind(
        &self,
    ) -> Option<tss_esapi::constants::response_code::Tss2ResponseCodeKind> {
        let Self::Other(OtherError(kind)) = self else {
            return None;
        };
        let (OtherErrorKind::Tss(tss_esapi::Error::Tss2Error(response_code))
        | OtherErrorKind::MessageBuffer(tss::message_buffer::Error::Tss(
            tss_esapi::Error::Tss2Error(response_code),
        ))) = kind
        else {
            return None;
        };

        response_code.kind()
    }
}

/// An optional parameter of an attestation request, as named by [`Error::ParameterTooLarge`]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttestationParameter {
    /// The user data
    UserData,
    /// The nonce
    Nonce,
    /// The public key
    PublicKey,
}

impl std::fmt::Display for AttestationParameter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UserData => "user data",
            Self::Nonce => "nonce",
            Self::PublicKey => "public key",
        })
    }
}

/// Failure of opening a TPM transport, naming which one and its path
#[derive(thiserror::Error, Debug)]
#[error("could not open the TPM {transport} {device_path:?}")]
pub struct OpenError {
    pub(crate) transport: Transport,
    pub(crate) device_path: std::path::PathBuf,
    pub(crate) source: OpenErrorKind,
}

impl OpenError {
    /// Path of the TPM transport that could not be opened
    #[must_use]
    pub fn device_path(&self) -> &std::path::Path {
        &self.device_path
    }
}

/// Which TPM transport failed to open, as only the device is busy while another holds it
#[derive(Debug, Clone, Copy)]
pub(crate) enum Transport {
    /// The kernel resource manager, which admits many users at a time
    ResourceManager,
    /// The TPM device itself, which admits a single user
    Device,
}

impl std::fmt::Display for Transport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ResourceManager => "resource manager",
            Self::Device => "device",
        })
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
    Tss(tss_esapi::Error),
    #[error(transparent)]
    MessageBuffer(tss::message_buffer::Error),
    #[error(transparent)]
    NsmRequest(raw::Error),
}
