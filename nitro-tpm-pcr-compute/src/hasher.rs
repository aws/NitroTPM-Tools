// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// A wrapper around an AWS-LC digest context in order to be able to implement the external
/// digest::Update trait, which is required by authenticode
pub(crate) struct Hasher {
    inner: aws_lc_rs::digest::Context,
}

impl Hasher {
    pub(crate) fn new(algorithm: &'static aws_lc_rs::digest::Algorithm) -> Self {
        Self {
            inner: aws_lc_rs::digest::Context::new(algorithm),
        }
    }

    pub(crate) fn finalize(self) -> aws_lc_rs::digest::Digest {
        self.inner.finish()
    }
}

impl digest::Update for Hasher {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
}
