// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// TCG TPM v2.0 Provisioning Guidance, Table 2: Reserved Handles for TPM Provisioning Fundamental Elements
const ENDORSEMENT_KEY_RSA2048_HANDLE: u32 = 0x81010001;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    TpmManager(#[from] crate::tpm_manager::Error),
    #[error(transparent)]
    Tss(#[from] tss_esapi::Error),
    #[error(transparent)]
    AwsLc(#[from] aws_lc_rs::error::KeyRejected),
    #[error(transparent)]
    Asn1Der(#[from] picky_asn1_der::Asn1DerError),
}

/// Get the handle and public encryption key of the pre-provisioned endorsement key
pub(crate) fn endorsement_key(
    tpm_manager: &std::cell::RefCell<crate::TpmManager>,
) -> Result<
    (
        tss_esapi::handles::TpmHandle,
        aws_lc_rs::rsa::PublicEncryptingKey,
    ),
    Error,
> {
    let mut tpm_manager_ref = tpm_manager.borrow_mut();
    let context = tpm_manager_ref.tss()?;

    let tpm_handle = ENDORSEMENT_KEY_RSA2048_HANDLE.try_into()?;
    let object_handle = context.tr_from_tpm_public(tpm_handle)?;
    let (public, _, _) = context.read_public(object_handle.into())?;
    let public_encryption_key = aws_lc_rs::rsa::PublicEncryptingKey::from_der(
        &picky_asn1_der::to_vec(&picky_asn1_x509::SubjectPublicKeyInfo::try_from(public)?)?,
    )?;

    Ok((tpm_handle, public_encryption_key))
}
