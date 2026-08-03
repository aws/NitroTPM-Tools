// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Abstraction for the TPM2 AWS NSM Vendor Command
//!
//! Provides a high-level interface for the TPM2 AWS vendor command that is used to send NSM
//! attestation requests.
//!
//! Everything goes through the kernel resource manager, which admits many users at a time, so a
//! concurrent invocation cannot take the TPM away mid-request. Only the vendor command can be
//! refused there, because a kernel before 6.3 masks the vendor bit off the command codes the TPM
//! reports and so never matches one, and the request then falls back to the TPM device, which
//! admits a single user. Both paths are configurable through TPM_RESOURCE_MANAGER_DEVICE and
//! TPM_DEVICE.

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

    let tpm_device_path = std::path::PathBuf::from(
        std::env::var_os("TPM_DEVICE").unwrap_or_else(|| "/dev/tpm0".into()),
    );
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

    let available = context
        .get_tpm_property(tss_esapi::constants::property_tag::PropertyTag::NvIndexMax)
        .map_err(Error::from_tss)?
        .and_then(|nv_index_max| usize::try_from(nv_index_max).ok())
        .ok_or_else(|| {
            Error::from_tss(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::WrongValueFromTpm,
            ))
        })?;

    if available < tss::message_buffer::SIZE {
        return Err(Error::NvIndexSizeInsufficient { available });
    }

    let password_session_handle =
        tss_esapi::interface_types::session_handles::AuthSession::Password;
    context.execute_with_session(Some(password_session_handle), |context| {
        let message_buffer = tss::MessageBuffer::from_request(context, &nsm_request)?;

        let send_nsm_request = |device_path| {
            let mut tpm = raw::Tpm::new(device_path).map_err(|error| OpenError {
                device_path: device_path.into(),
                source: error.into(),
            })?;

            Ok::<_, Error>(tpm.nsm_request(message_buffer.index(), message_buffer.auth())?)
        };

        send_nsm_request(&tpm_resource_manager_device_path).or_else(|error| {
            if !error.is_unsupported_command() {
                return Err(error);
            }

            send_nsm_request(&tpm_device_path)
        })?;

        match message_buffer.into_response()? {
            nsm_api::Response::Attestation { document } => Ok(document),
            nsm_api::Response::Error(error_code) => Err(Error::NsmErrorResponse(error_code)),
            _ => Err(Error::InvalidNsmResponse),
        }
    })
}
