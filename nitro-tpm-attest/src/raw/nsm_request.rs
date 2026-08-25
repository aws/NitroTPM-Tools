// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Tpm(#[from] super::tpm::Error),
    #[error(transparent)]
    TpmManager(#[from] crate::tpm_manager::Error),
}

pub(crate) fn nsm_request(
    tpm_manager: &std::cell::RefCell<crate::TpmManager>,
    message_buffer_index: tss_esapi::handles::NvIndexTpmHandle,
    message_buffer_auth: &tss_esapi::structures::Auth,
) -> Result<(), Error> {
    tpm_manager
        .borrow_mut()
        .raw()?
        .nsm_request(message_buffer_index, message_buffer_auth)?;

    Ok(())
}
