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

/// Failure of the binary, which is either the attestation itself or an I/O operation around it
#[derive(thiserror::Error, Debug)]
enum Error {
    #[error(transparent)]
    Attestation(#[from] nitro_tpm_attest::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Error {
    /// Exit code for the failure
    ///
    /// A failure that the library reports a retry might fix exits with the 75 that sysexits.h
    /// reserves for a temporary failure, so that a caller can tell it apart from any other.
    fn exit_code(&self) -> std::process::ExitCode {
        const EX_TEMPFAIL: u8 = 75;

        match self {
            Self::Attestation(error) if error.is_temporarily_unavailable() => EX_TEMPFAIL.into(),
            _ => std::process::ExitCode::FAILURE,
        }
    }
}

fn main() -> std::process::ExitCode {
    let Err(error) = run() else {
        return std::process::ExitCode::SUCCESS;
    };
    let exit_code = error.exit_code();

    // Reporting the failure must not replace its exit code with a panic of its own
    let _ = std::io::Write::write_fmt(
        &mut std::io::stderr(),
        format_args!("Error: {:?}\n", anyhow::Error::from(error)),
    );

    exit_code
}

fn run() -> Result<(), Error> {
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
