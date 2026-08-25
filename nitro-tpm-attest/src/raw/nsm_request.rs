// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Tpm(#[from] super::tpm::Error),
    #[error(transparent)]
    AuthSession(#[from] super::auth_session::Error),
    #[error(transparent)]
    TpmManager(#[from] crate::tpm_manager::Error),
    #[error(transparent)]
    Tss(#[from] tss_esapi::Error),
}

pub(crate) fn nsm_request(
    tpm_manager: &std::cell::RefCell<crate::TpmManager>,
    message_buffer_index: tss_esapi::handles::NvIndexTpmHandle,
    message_buffer_auth: &tss_esapi::structures::Auth,
    message_buffer_name: &tss_esapi::structures::Name,
) -> Result<(), Error> {
    let (auth_session, nonce_tpm) = super::AuthSession::new(tpm_manager)?;
    let cp_hash = cp_hash(message_buffer_name)?;
    let auth_area = auth_session.auth_area(message_buffer_auth, &nonce_tpm, &cp_hash)?;

    tpm_manager
        .borrow_mut()
        .raw()?
        .nsm_request(message_buffer_index, &auth_area)?;

    Ok(())
}

// 18.7 Command Parameter Hash (cpHash)
fn cp_hash(
    message_buffer_name: &tss_esapi::structures::Name,
) -> tss_esapi::Result<tss_esapi::structures::Digest> {
    let mut hasher = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA512);

    hasher.update(&super::tpm::TPM2_VENDOR_AWS_NSM_REQUEST.to_be_bytes());
    // NV auth
    hasher.update(message_buffer_name.value());
    // NV index
    hasher.update(message_buffer_name.value());

    tss_esapi::structures::Digest::try_from(hasher.finish().as_ref())
}
