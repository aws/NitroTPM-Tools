# NitroTPM Attest

This utility enables you to retrieve a signed attestation document from the NitroTPM. You can use the attestation document to perform NitroTPM attestation and establish trust with AWS KMS or other external service.
This package includes both a command-line interface (CLI) and a Rust crate that can be used to interact with the TPM2 device to perform attestation requests.

## Usage

### Basic attestation document request

When you request the attestation document, you can specify an optional public key, user data, and nonce. These will be included in the attestation document returned by the NitroTPM.
The public key can be used by AWS KMS or an external service to encrypt response data before it is returned. This ensures that only the intended recipient, which has possession of the private key, can decrypt the data.
The user data can be used to deliver any additional signed data to the external service.
The nonce can be used to set up challenge-response authentication to help avoid impersonation attacks.

To request an attestation document with the optional public key, user data, and nonce:

```console
cargo run --package nitro-tpm-attest -- \
    --user-data <user-data-file> \
    --nonce <nonce-file> \
    --public-key <public-key-file>
```

### Owner authorization

The utility defines and undefines its NV index under the TPM's owner hierarchy, whose authorization value is empty on a NitroTPM by default. If one has been set with `tpm2_changeauth -c owner`, pass the file holding it:

```console
cargo run --package nitro-tpm-attest -- --owner-auth owner-auth.file
```

A file is taken rather than an argument value so that its permissions restrict who reads it and it stays out of the process arguments.

The file is used byte for byte. A trailing newline, such as the one that `echo` adds, becomes part of the value. To create the file without a trailing newline, use `printf %s`:

```console
(umask 077 && printf %s '<owner-auth>' > owner-auth.file)
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

### Retrying a temporary failure

An attestation holds an NV index in the TPM for its duration, and, on an older kernel whose resource manager does not carry the vendor command, the TPM device itself. A TPM has little NV memory to spare and the device admits a single user, so requests running next to each other can run out of either. A request that failed for that reason reports a temporary failure, 75, and is worth repeating once the other request is done.

```sh
attempts=5
for attempt in $(seq "$attempts"); do
    nitro-tpm-attest > attestation-document.bin && break
    rc=$?
    [ "$rc" -eq 75 ] && [ "$attempt" -lt "$attempts" ] || exit "$rc"
    sleep 1
done
```

A systemd service can key on the same code:

```ini
[Unit]
StartLimitBurst=5
StartLimitIntervalSec=60

[Service]
Type=exec
ExecStart=/usr/bin/nitro-tpm-attest
StandardOutput=truncate:/run/attestation-document.bin
RestartForceExitStatus=TEMPFAIL
RestartSec=1
```

### TPM devices

Both the TSS and the NSM vendor command go through the kernel resource manager, `/dev/tpmrm0`, which admits many users at a time. A kernel before 6.3 does not carry the vendor command there, so the vendor command falls back to `/dev/tpm0`, which admits a single user. Either path can be redirected:

| Variable | Default | Purpose |
| --- | --- | --- |
| `TPM_RESOURCE_MANAGER_DEVICE` | `/dev/tpmrm0` | The resource manager both the TSS and the vendor command go through |
| `TPM_DEVICE` | `/dev/tpm0` | The device the vendor command falls back to |
