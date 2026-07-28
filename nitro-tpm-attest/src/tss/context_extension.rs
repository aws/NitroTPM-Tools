// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Custom functions for the TSS context

pub(super) trait ContextExtension {
    /// Find a free handle in the given range
    fn find_free_handle(
        &mut self,
        first_handle: u32,
        last_handle: u32,
    ) -> tss_esapi::Result<Option<tss_esapi::handles::TpmHandle>>;

    /// Execute a function with a salted authorization session
    fn execute_with_salted_auth_session<F, T, E>(
        &mut self,
        salt_key_tpm_handle: tss_esapi::handles::TpmHandle,
        function: F,
    ) -> std::result::Result<T, E>
    where
        F: FnOnce(&mut tss_esapi::Context) -> std::result::Result<T, E>,
        E: From<tss_esapi::Error>;
}

impl ContextExtension for tss_esapi::Context {
    fn find_free_handle(
        &mut self,
        first_handle: u32,
        last_handle: u32,
    ) -> tss_esapi::Result<Option<tss_esapi::handles::TpmHandle>> {
        let Some(property_count) = last_handle
            .checked_sub(first_handle)
            .and_then(|span| span.checked_add(1))
        else {
            return Ok(None);
        };
        let tpm_handles = self
            .execute_without_session(|context| {
                context.get_capability(
                    tss_esapi::constants::CapabilityType::Handles,
                    first_handle,
                    property_count,
                )
            })
            .and_then(|(capability_data, _)| match capability_data {
                tss_esapi::structures::CapabilityData::Handles(tpm_handles) => Ok(tpm_handles),
                _ => Err(tss_esapi::Error::WrapperError(
                    tss_esapi::WrapperErrorKind::WrongValueFromTpm,
                )),
            })?
            .into_inner()
            .into_iter()
            .map(u32::from)
            .collect::<std::collections::HashSet<_>>();

        (first_handle..=last_handle)
            .find(|tpm_handle| !tpm_handles.contains(tpm_handle))
            .map(tss_esapi::handles::TpmHandle::try_from)
            .transpose()
    }

    fn execute_with_salted_auth_session<F, T, E>(
        &mut self,
        salt_key_tpm_handle: tss_esapi::handles::TpmHandle,
        function: F,
    ) -> std::result::Result<T, E>
    where
        F: FnOnce(&mut tss_esapi::Context) -> std::result::Result<T, E>,
        E: From<tss_esapi::Error>,
    {
        let salt_key_handle = self.tr_from_tpm_public(salt_key_tpm_handle)?.into();
        let auth_session = self
            .start_auth_session(
                Some(salt_key_handle),
                None,
                None,
                tss_esapi::constants::SessionType::Hmac,
                tss_esapi::structures::SymmetricDefinition::AES_128_CFB,
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha512,
            )?
            .ok_or(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::WrongValueFromTpm,
            ))?;
        let (session_attributes, session_attributes_mask) =
            tss_esapi::attributes::SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();

        self.tr_sess_set_attributes(auth_session, session_attributes, session_attributes_mask)
            .or_else(|error| {
                self.flush_context(tss_esapi::handles::SessionHandle::from(auth_session).into())?;

                Err(error)
            })?;

        let result = self.execute_with_session(Some(auth_session), function);

        self.flush_context(tss_esapi::handles::SessionHandle::from(auth_session).into())?;

        result
    }
}
