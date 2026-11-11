// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Custom function for TPM response codes

pub(crate) trait ResponseCodeExtension {
    /// Whether the TPM did not finish the command and asks to submit it again
    fn is_retryable(&self) -> bool;
}

impl ResponseCodeExtension for tss_esapi::constants::response_code::Tss2ResponseCode {
    fn is_retryable(&self) -> bool {
        matches!(
            self.kind(),
            Some(
                tss_esapi::constants::response_code::Tss2ResponseCodeKind::Retry
                    | tss_esapi::constants::response_code::Tss2ResponseCodeKind::Testing
                    | tss_esapi::constants::response_code::Tss2ResponseCodeKind::Yielded
            )
        )
    }
}
