// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/// Decrypt a ciphertext with an AWS KMS managed key that is conditional on the instance state
#[derive(clap::Parser)]
struct Arguments {
    /// KMS key ID
    #[arg(short, long)]
    key_id: String,
    /// Base64 encoded ciphertext (like outputted by the AWS CLI)
    ciphertext: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arguments: Arguments = clap::Parser::parse();

    let private_key = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048)?)?;
    let public_key = private_key.public_key_to_der()?;

    let attestation_document =
        nitro_tpm_attest::attestation_document(None, None, Some(public_key))?;

    let plaintext = decrypt(
        &arguments.key_id,
        &arguments.ciphertext,
        attestation_document,
        private_key,
    )
    .await?;

    print!("{plaintext}");

    Ok(())
}

async fn decrypt(
    key_id: &str,
    ciphertext: &str,
    attestation_document: Vec<u8>,
    private_key: openssl::pkey::PKey<openssl::pkey::Private>,
) -> anyhow::Result<String> {
    let ciphertext = <base64ct::Base64 as base64ct::Encoding>::decode_vec(ciphertext)?;
    let recipient_info = aws_sdk_kms::types::RecipientInfo::builder()
        .set_key_encryption_algorithm(Some(
            aws_sdk_kms::types::KeyEncryptionMechanism::RsaesOaepSha256,
        ))
        .set_attestation_document(Some(attestation_document.into()))
        .build();

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let response = aws_sdk_kms::Client::new(&config)
        .decrypt()
        .key_id(key_id)
        .recipient(recipient_info)
        .ciphertext_blob(ciphertext.into())
        .send()
        .await?;

    let ciphertext_for_recipient = response
        .ciphertext_for_recipient()
        .ok_or_else(|| anyhow::anyhow!("could not get ciphertext for recipient"))?
        .as_ref();
    let plaintext = openssl::cms::CmsContentInfo::from_der(ciphertext_for_recipient)?
        .decrypt_without_cert_check(&private_key)?;

    Ok(String::from_utf8(plaintext)?)
}
