// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encapsulates all raw TPM operations

pub mod tpm;

pub(crate) use tpm::{Error, Tpm};
