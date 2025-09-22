// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    // While tss-esapi 7.6 supports a minimum TSS version of 2.4.6, behavior between major version
    // differs significantly
    let tss_version_requirement =
        semver::VersionReq::parse("4.0.0").expect("Failed to parse version requirement");

    let tss_version_string =
        std::env::var("DEP_TSS2_ESYS_VERSION").expect("DEP_TSS2_ESYS_VERSION not set");
    let tss_version =
        semver::Version::parse(&tss_version_string).expect("Failed to parse DEP_TSS2_ESYS_VERSION");

    assert!(
        tss_version_requirement.matches(&tss_version),
        "TPM2 Software Stack (TSS) version {tss_version} not supported, version requirement: {tss_version_requirement}",
    );

    // Allow static linking
    println!("cargo:rustc-link-arg=-ltss2-tcti-device");
}
