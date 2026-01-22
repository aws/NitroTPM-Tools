// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persists the endorsement key handle, so it is not flushed by tss-esapi-rs and is usable by the
//! raw command

use super::ContextExtension as _;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("could not find free persistent handle")]
    PersistentHandleCapacity,
    #[error(transparent)]
    TpmManager(#[from] crate::tpm_manager::Error),
    #[error(transparent)]
    Tss(#[from] tss_esapi::Error),
    #[error(transparent)]
    AwsLc(#[from] aws_lc_rs::error::KeyRejected),
    #[error(transparent)]
    Asn1Der(#[from] picky_asn1_der::Asn1DerError),
}

pub(crate) struct EndorsementKey<'a> {
    tpm_manager: &'a std::cell::RefCell<crate::TpmManager>,
    persistent_tpm_handle: tss_esapi::handles::PersistentTpmHandle,
    endorsement_key_create_result: tss_esapi::structures::CreatePrimaryKeyResult,
}

impl<'a> EndorsementKey<'a> {
    pub(crate) fn new(
        tpm_manager: &'a std::cell::RefCell<crate::TpmManager>,
    ) -> Result<Self, Error> {
        let endorsement_key_template =
            tss_esapi::abstraction::ek::create_ek_public_from_default_template_2(
                tss_esapi::abstraction::AsymmetricAlgorithmSelection::Rsa(
                    tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa2048,
                ),
                None,
            )?;

        let mut tpm_manager_ref = tpm_manager.borrow_mut();
        let context = tpm_manager_ref.tss()?;
        let persistent_tpm_handle = context
            .find_free_handle(
                tss_esapi::constants::tss::TPM2_PERSISTENT_FIRST,
                tss_esapi::constants::tss::TPM2_PERSISTENT_LAST,
            )?
            .ok_or(Error::PersistentHandleCapacity)?
            .try_into()?;

        let endorsement_key_create_result = context.execute_with_nullauth_session(|context| {
            let endorsement_key_create_result = context.create_primary(
                tss_esapi::interface_types::resource_handles::Hierarchy::Endorsement,
                endorsement_key_template,
                None,
                None,
                None,
                None,
            )?;

            context.evict_control(
                tss_esapi::interface_types::resource_handles::Provision::Owner,
                endorsement_key_create_result.key_handle.into(),
                tss_esapi::interface_types::dynamic_handles::Persistent::Persistent(
                    persistent_tpm_handle,
                ),
            )?;

            Ok::<_, tss_esapi::Error>(endorsement_key_create_result)
        })?;

        Ok(Self {
            tpm_manager,
            persistent_tpm_handle,
            endorsement_key_create_result,
        })
    }

    pub(crate) fn tpm_handle(&self) -> tss_esapi::handles::TpmHandle {
        self.persistent_tpm_handle.into()
    }

    pub(crate) fn public_encryption_key(
        &self,
    ) -> Result<aws_lc_rs::rsa::PublicEncryptingKey, Error> {
        Ok(aws_lc_rs::rsa::PublicEncryptingKey::from_der(
            &picky_asn1_der::to_vec(&picky_asn1_x509::SubjectPublicKeyInfo::try_from(
                self.endorsement_key_create_result.out_public.clone(),
            )?)?,
        )?)
    }
}

impl Drop for EndorsementKey<'_> {
    fn drop(&mut self) {
        self.tpm_manager
            .borrow_mut()
            .tss()
            .expect("Failed to get context")
            .execute_with_nullauth_session(|context| {
                let object_handle = context
                    .tr_from_tpm_public(self.tpm_handle())
                    .expect("Failed to get TPM handle");

                context.evict_control(
                    tss_esapi::interface_types::resource_handles::Provision::Owner,
                    object_handle,
                    tss_esapi::interface_types::dynamic_handles::Persistent::Persistent(
                        self.persistent_tpm_handle,
                    ),
                )
            })
            .expect("Failed to evict persistent handle");
    }
}
