// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Mimic the Nitro Enclave build info output
#[derive(serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct BuildInfo {
    measurements: Measurements,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "PascalCase")]
struct Measurements {
    hash_algorithm: String,
    #[serde(flatten, serialize_with = "serialize_pcr_map")]
    pcrs: std::collections::BTreeMap<u8, aws_lc_rs::digest::Digest>,
}

impl BuildInfo {
    pub(crate) fn new(hash_algorithm: &str) -> Self {
        Self {
            measurements: Measurements {
                hash_algorithm: hash_algorithm.to_owned(),
                pcrs: Default::default(),
            },
        }
    }

    pub(crate) fn add_measurement(&mut self, index: u8, digest: aws_lc_rs::digest::Digest) {
        self.measurements.pcrs.insert(index, digest);
    }
}

impl std::fmt::Display for BuildInfo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string_pretty(&self).map_err(|_| std::fmt::Error)?;

        write!(formatter, "{json}")
    }
}

fn serialize_pcr_map<S>(
    map: &std::collections::BTreeMap<u8, aws_lc_rs::digest::Digest>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap as _;
    use std::fmt::Write as _;

    let mut map_serializer = serializer.serialize_map(Some(map.len()))?;

    for (index, digest) in map {
        let digest_hex: String = digest.as_ref().iter().fold(
            String::with_capacity(digest.as_ref().len() * 2),
            |mut digest_hex, byte| {
                let _ = write!(digest_hex, "{byte:02x}");
                digest_hex
            },
        );
        map_serializer.serialize_entry(&format!("PCR{index}"), &digest_hex)?;
    }

    map_serializer.end()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_the_hash_algorithm_and_the_measurements() {
        let mut build_info = BuildInfo::new(crate::ALGORITHM_NAME);

        // Out of order, as the output is sorted by index
        build_info.add_measurement(12, aws_lc_rs::digest::digest(crate::ALGORITHM, b"pcr12"));
        build_info.add_measurement(4, aws_lc_rs::digest::digest(crate::ALGORITHM, b"pcr4"));

        assert_eq!(
            build_info.to_string(),
            r#"{
  "Measurements": {
    "HashAlgorithm": "SHA384",
    "PCR4": "baa47e59f5ab7e026ffe0b85cf86e5a34494da6fb5a10e91eeb7ab839764a0d280a3ce5fd3dfc9c1225b75aa7e4820ca",
    "PCR12": "38620c0ff9b8a29cd903205c2ed1e24a92eb4e8a25668c5b59a5e50960f0df0aee70f0c33c10ca645acae477261f1a99"
  }
}"#
        );
    }
}
