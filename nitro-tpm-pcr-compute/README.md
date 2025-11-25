# NitroTPM PCR Compute

This utility enables you to precompute NitroTPM Platform Configuration Register (PCR) 4, 7, and 12 values based on a Unified Kernel Image (UKI). These are the same PCR values that are included in the attestation document returned by the NitroTPM.
You can use the precomputed PCR values to create AWS KMS key policies that grant or deny key access based on these values.
The utility supports PE/COFF images in both standard boot and UEFI Secure Boot environments. In Secure Boot mode, these images can be signed with X.509 certificates.
Measurements are precomputed according to the TCG PC Client Platform Firmware Profile Specification.

## Usage

### Standard boot

To precompute measurements for standard boot:

```console
cargo run --package nitro-tpm-pcr-compute -- --image <UKI.efi>
```

### UEFI Secure Boot

To precompute measurements with UEFI Secure Boot enabled:

```console
cargo run --package nitro-tpm-pcr-compute -- \
    --image <UKI.efi> \
    --PK <PK.esl> \
    --KEK <KEK.esl> \
    --db <db.esl>
```

## Output

The utility returns measurements in the following JSON format:

```json
{
  "Measurements": {
    "HashAlgorithm": "SHA384",
    "PCR4": "<hex string>",
    "PCR7": "<hex string>",
    "PCR12": "<hex string>"
  }
}
```

## References

- [TCG PC Client Platform Firmware Profile Specification](https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/)
- [UEFI Secure Boot for Amazon EC2 instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/uefi-secure-boot.html)

