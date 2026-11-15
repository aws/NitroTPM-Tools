// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) struct Pcr {
    digest: aws_lc_rs::digest::Digest,
}

impl Pcr {
    pub(crate) fn new(algorithm: &'static aws_lc_rs::digest::Algorithm) -> Self {
        Self {
            digest: aws_lc_rs::digest::Digest::import_less_safe(
                &vec![0u8; algorithm.output_len],
                algorithm,
            )
            .expect("a digest of the algorithm's output length should import"),
        }
    }

    pub(crate) fn extend(
        &mut self,
        measurement: &aws_lc_rs::digest::Digest,
    ) -> &aws_lc_rs::digest::Digest {
        self.digest = aws_lc_rs::digest::digest(
            self.digest.algorithm(),
            &[self.digest.as_ref(), measurement.as_ref()].concat(),
        );

        &self.digest
    }
}

impl From<Pcr> for aws_lc_rs::digest::Digest {
    fn from(pcr: Pcr) -> Self {
        pcr.digest
    }
}
