// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::ContextExtension as _;
use aws_nitro_enclaves_nsm_api::api as nsm_api;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("could not find free NV index handle")]
    NvIndexHandleCapacity,
    #[error(transparent)]
    TpmManager(#[from] crate::tpm_manager::Error),
    #[error(transparent)]
    Tss(#[from] tss_esapi::Error),
    #[error(transparent)]
    Serialization(#[from] ciborium::ser::Error<std::io::Error>),
    #[error(transparent)]
    Deserialization(#[from] ciborium::de::Error<std::io::Error>),
    #[error(transparent)]
    AwsLc(#[from] aws_lc_rs::error::Unspecified),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub(crate) struct MessageBuffer<'a> {
    tpm_manager: &'a std::cell::RefCell<crate::TpmManager>,
    nv_index_tpm_handle: tss_esapi::handles::NvIndexTpmHandle,
    salt_key_tpm_handle: tss_esapi::handles::TpmHandle,
    nv_index_auth: tss_esapi::structures::Auth,
}

impl<'a> MessageBuffer<'a> {
    /// Defines an input/output message buffer and returns it's unique name (after the the NSM
    /// request was written to it) alongside the buffer itself
    pub(crate) fn from_request(
        tpm_manager: &'a std::cell::RefCell<crate::TpmManager>,
        salt_key_tpm_handle: tss_esapi::handles::TpmHandle,
        nsm_request: &nsm_api::Request,
    ) -> Result<(Self, tss_esapi::structures::Name), Error> {
        // The plain attestation document (without any optional parameters) will be almost 5 KiB and
        // the optional parameters are each limited to 1 KiB
        const SIZE: usize = 8192;

        let mut nv_index_auth = vec![0u8; tss_esapi::structures::Auth::MAX_SIZE];

        aws_lc_rs::rand::fill(&mut nv_index_auth)?;

        let nv_index_auth = tss_esapi::structures::Auth::try_from(nv_index_auth)?;

        let mut tpm_manager_ref = tpm_manager.borrow_mut();
        let context = tpm_manager_ref.tss()?;
        let nv_index_tpm_handle = tss_esapi::handles::NvIndexTpmHandle::try_from(
            context
                .find_free_handle(
                    tss_esapi::constants::tss::TPM2_NV_INDEX_FIRST,
                    tss_esapi::constants::tss::TPM2_NV_INDEX_LAST,
                )?
                .ok_or(Error::NvIndexHandleCapacity)?,
        )?;

        let nv_index_attributes = tss_esapi::attributes::nv_index::NvIndexAttributes::builder()
            .with_auth_read(true)
            .with_auth_write(true)
            .build()?;
        let nv_public = tss_esapi::structures::NvPublic::builder()
            .with_nv_index(nv_index_tpm_handle)
            .with_index_name_algorithm(
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha512,
            )
            .with_index_attributes(nv_index_attributes)
            .with_data_area_size(SIZE)
            .build()?;

        let name = context.execute_with_salted_auth_session(salt_key_tpm_handle, |context| {
            let nv_index_handle = context.nv_define_space(
                tss_esapi::interface_types::resource_handles::Provision::Owner,
                Some(nv_index_auth.clone()),
                nv_public,
            )?;

            ciborium::into_writer(
                &nsm_request,
                &mut tss_esapi::abstraction::nv::NvOpenOptions::ExistingIndex {
                    nv_index_handle: nv_index_tpm_handle,
                    auth_handle: tss_esapi::interface_types::resource_handles::NvAuth::NvIndex(
                        nv_index_handle,
                    ),
                }
                .open(context)?,
            )?;

            let nv_index_handle = context.tr_from_tpm_public(nv_index_tpm_handle.into())?;
            let name = context
                .nv_read_public(nv_index_handle.into())
                .map(|(_, name)| name)?;

            Ok::<_, Error>(name)
        })?;

        Ok((
            Self {
                tpm_manager,
                nv_index_tpm_handle,
                salt_key_tpm_handle,
                nv_index_auth,
            },
            name,
        ))
    }

    /// Reads the NSM response from the message buffer and drops the buffer afterwards
    pub(crate) fn into_response(self) -> Result<nsm_api::Response, Error> {
        self.tpm_manager
            .borrow_mut()
            .tss()?
            .execute_with_salted_auth_session(self.salt_key_tpm_handle, |context| {
                let nv_index_handle =
                    context.tr_from_tpm_public(self.nv_index_tpm_handle.into())?;

                context.tr_set_auth(nv_index_handle, self.nv_index_auth.clone())?;

                Ok(ciborium::from_reader(
                    tss_esapi::abstraction::nv::NvOpenOptions::ExistingIndex {
                        nv_index_handle: self.nv_index_tpm_handle,
                        auth_handle: tss_esapi::interface_types::resource_handles::NvAuth::NvIndex(
                            nv_index_handle.into(),
                        ),
                    }
                    .open(context)?,
                )?)
            })
    }

    pub(crate) fn index(&self) -> tss_esapi::handles::NvIndexTpmHandle {
        self.nv_index_tpm_handle
    }

    pub(crate) fn auth(&self) -> &tss_esapi::structures::Auth {
        &self.nv_index_auth
    }
}

impl Drop for MessageBuffer<'_> {
    fn drop(&mut self) {
        self.tpm_manager
            .borrow_mut()
            .tss()
            .expect("Failed to get context")
            .execute_with_nullauth_session(|context| {
                let nv_index_handle = context
                    .tr_from_tpm_public(self.nv_index_tpm_handle.into())
                    .expect("Failed to construct TPM into TSS handle");

                context.nv_undefine_space(
                    tss_esapi::interface_types::resource_handles::Provision::Owner,
                    nv_index_handle.into(),
                )
            })
            .expect("Failed to undefine message buffer");
    }
}
