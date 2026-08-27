// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The crate's error types

use crate::{nsm_api, raw, tss};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid NSM response")]
    InvalidNsmResponse,
    #[error("NSM error response: {0:?}")]
    NsmErrorResponse(nsm_api::ErrorCode),
    #[error(transparent)]
    MessageBuffer(#[from] tss::message_buffer::Error),
    #[error(transparent)]
    NsmRequest(#[from] raw::nsm_request::Error),
    #[error(transparent)]
    Tss(#[from] tss_esapi::Error),
}
