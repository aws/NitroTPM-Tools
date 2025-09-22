# NitroTPM Attest

This utility enables you to retrieve a signed attestation document from the NitroTPM. You can use the attestation document to perform NitroTPM attestation and establish trust with AWS KMS or other external service.
This package includes both a command-line interface (CLI) and a Rust crate that can be used to interact with the TPM2 device to perform attestation requests.

## Usage

### Basic attestation document request

When you request the attestation document, you can specify an optional public key, user data, and nonce. These will be included in the attestation document returned by the NitroTPM.
The public key can be used by AWS KMS or an external service to encrypt response data before it is returned. This ensures that only the intended recipient, which has possession of the private key, can decrypt the data.
The user data can be used to deliver any additional signed data to the external service.
The nonce can be used to set up challenge-repsonse authentication to help avoid impersonation attacks.

To request an attestation document with the optional public key, user data, and nonce:

```console
cargo run --package nitro-tpm-attest -- \
    --user-data <user-data-file> \
    --nonce <nonce-file> \
    --public-key <public-key-file>
```

### AWS KMS integration

AWS KMS integration can either be achieved using the AWS SDK or using the AWS CLI, and by attaching the attestation document to the request.

#### AWS SDK

The following example shows how to perform an AWS KMS Decrypt operation using the AWS SDK.

```console
cargo run --example nitro-tpm-kms-decrypt -- \
    --key-id <KMS-key-ID> \
    <Base64-encoded-ciphertext>
```

#### AWS CLI

The following example script demonstrates how to generate a private/public key pair, request an attestation document, and then perform an AWS KMS Decrypt operation using the AWS CLI.

```bash
# 1. Generate RSA key pair. The public key will be included in the attestation document request.
private_key="$(openssl genrsa | base64 --wrap 0)"
public_key="$(openssl rsa \
    -pubout \
    -in <(base64 --decode <<< "$private_key") \
    -outform DER \
    2> /dev/null \
    | base64 --wrap 0)"

# 2. Request an attestation document and provide the public key. The public key will be included in the returned attestation document.
attestation_doc="$(nitro-tpm-attest \
    --public-key <(base64 --decode <<< "$public_key") \
    | base64 --wrap 0)"

# 3. Perform the AWS KMS Decrypt request and specify the attestation document. The CiphertextForRecipient returned by AWS KMS is encrypted with the public key in the attestation document.
plaintext_cms=$(aws kms decrypt \
    --key-id "<KMS-key-ID>" \
    --recipient "KeyEncryptionAlgorithm=RSAES_OAEP_SHA_256,AttestationDocument=$attestation_doc" \
    --ciphertext-blob fileb://<(base64 --decode <<< "<Base64-encoded-ciphertext>") \
    --output text \
    --query CiphertextForRecipient)

# 4. Decrypt the content encrypted plaintext returned by AWS KMS using the private key.
openssl cms \
    -decrypt \
    -inkey <(base64 --decode <<< "$private_key") \
    -inform DER \
    -in <(base64 --decode <<< "$plaintext_cms")
```

## Static Builds

For static linking requirements, a Docker-based build environment is provided that can be used to statically link the TPM2 Software Stack (TSS2) and other dependencies.

```console
docker build --file docker/builder.Dockerfile --tag nitro-tpm-tools-builder .
docker run --rm --tty --volume cargo-cache:/root/.cargo/registry --volume $PWD:/mnt nitro-tpm-tools-builder cargo build --package nitro-tpm-attest --release
```
