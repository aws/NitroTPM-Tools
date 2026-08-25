// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Tpm(#[from] super::tpm::Error),
    #[error(transparent)]
    TpmManager(#[from] crate::tpm_manager::Error),
    #[error(transparent)]
    Tss(#[from] tss_esapi::Error),
    #[error(transparent)]
    AwsLc(#[from] aws_lc_rs::error::Unspecified),
}

pub(super) struct AuthSession<'a> {
    tpm_manager: &'a std::cell::RefCell<crate::TpmManager>,
    session_handle: tss_esapi::handles::TpmHandle,
}

impl<'a> AuthSession<'a> {
    /// Creates a new authorization session and returns the initial TPM nonce alongside it
    pub(crate) fn new(
        tpm_manager: &'a std::cell::RefCell<crate::TpmManager>,
    ) -> Result<(Self, tss_esapi::structures::Nonce), Error> {
        let mut nonce_caller = [0u8; tss_esapi::structures::Nonce::MAX_SIZE];

        aws_lc_rs::rand::fill(&mut nonce_caller)?;

        let nonce_caller = tss_esapi::structures::Nonce::try_from(nonce_caller.as_slice())?;

        let (session_handle, nonce_tpm) = tpm_manager.borrow_mut().raw()?.start_auth_session(
            None,
            None,
            &nonce_caller,
            tss_esapi::constants::session_type::SessionType::Hmac,
            tss_esapi::structures::SymmetricDefinition::Null,
            tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha512,
        )?;

        Ok((
            Self {
                tpm_manager,
                session_handle,
            },
            nonce_tpm,
        ))
    }

    pub(crate) fn auth_area(
        &self,
        auth_value: &tss_esapi::structures::Auth,
        nonce_tpm: &tss_esapi::structures::Nonce,
        cp_hash: &tss_esapi::structures::Digest,
    ) -> Result<Vec<u8>, Error> {
        let mut nonce_caller = [0u8; tss_esapi::structures::Nonce::MAX_SIZE];

        aws_lc_rs::rand::fill(&mut nonce_caller)?;

        let nonce_caller = tss_esapi::structures::Nonce::try_from(nonce_caller.as_slice())?;

        let (session_attributes, _) = tss_esapi::attributes::session::SessionAttributes::builder()
            // We manage the session ourselves, so we can also flush it when an error occurs
            .with_continue_session(true)
            .build();
        let session_attributes = tss_esapi::tss2_esys::TPMA_SESSION::from(session_attributes);

        let auth_hmac = auth_hmac(
            auth_value,
            cp_hash,
            &nonce_caller,
            nonce_tpm,
            session_attributes,
        );
        let auth_hmac = auth_hmac.as_ref();

        Ok([
            u32::from(self.session_handle).to_be_bytes().as_slice(),
            &(nonce_caller.len() as u16).to_be_bytes(),
            &nonce_caller,
            &session_attributes.to_be_bytes(),
            &(auth_hmac.len() as u16).to_be_bytes(),
            auth_hmac,
        ]
        .concat())
    }
}

impl Drop for AuthSession<'_> {
    fn drop(&mut self) {
        self.tpm_manager
            .borrow_mut()
            .raw()
            .expect("Could not get TPM device")
            .flush_context(self.session_handle)
            .expect("Could not flush auth session");
    }
}

// 19.6.9 Unbound and Unsalted Session Key Generation
fn auth_hmac(
    auth_value: &tss_esapi::structures::Auth,
    cp_hash: &tss_esapi::structures::Digest,
    nonce_caller: &tss_esapi::structures::Nonce,
    nonce_tpm: &tss_esapi::structures::Nonce,
    session_attributes: tss_esapi::tss2_esys::TPMA_SESSION,
) -> aws_lc_rs::hmac::Tag {
    let hmac_key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA512, auth_value);
    let mut signer = aws_lc_rs::hmac::Context::with_key(&hmac_key);

    signer.update(cp_hash.value());
    signer.update(nonce_caller);
    signer.update(nonce_tpm);
    signer.update(&[session_attributes]);

    signer.sign()
}
