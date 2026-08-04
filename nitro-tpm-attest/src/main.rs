// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Request a TPM attestation document from NitroTPM
#[derive(clap::Parser)]
#[command(version)]
struct Arguments {
    /// Path of user data to optionally include
    #[arg(short, long)]
    user_data: Option<std::path::PathBuf>,
    /// Path of a nonce to optionally include
    #[arg(short, long)]
    nonce: Option<std::path::PathBuf>,
    /// Path of a public key to optionally include
    #[arg(short, long)]
    public_key: Option<std::path::PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let arguments: Arguments = clap::Parser::parse();

    let user_data = arguments.user_data.map(std::fs::read).transpose()?;
    let nonce = arguments.nonce.map(std::fs::read).transpose()?;
    let public_key = arguments.public_key.map(std::fs::read).transpose()?;

    let attestation_document =
        nitro_tpm_attest::attestation_document(user_data, nonce, public_key)?;

    let mut stdout = std::io::stdout();

    std::io::Write::write_all(&mut stdout, &attestation_document)?;
    // Without this flush, the rest of the document would only be written at exit, where a failed
    // write is silently ignored
    std::io::Write::flush(&mut stdout)?;

    Ok(())
}
