// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) fn try_from(mut data: &[u8]) -> Option<Vec<EfiSignatureList>> {
    let mut efi_signature_lists = Vec::new();

    while !data.is_empty() {
        let (efi_signature_list, remaining_data) = EfiSignatureList::try_parse(data)?;

        efi_signature_lists.push(efi_signature_list);
        data = remaining_data;
    }

    Some(efi_signature_lists)
}

const GUID_SIZE: usize = std::mem::size_of::<uuid::Bytes>();

#[derive(Debug)]
pub(crate) struct EfiSignatureList {
    pub(crate) signature_type: uuid::Uuid,
    pub(crate) signatures: Vec<EfiSignatureData>,
}

impl EfiSignatureList {
    pub(crate) fn try_parse(data: &[u8]) -> Option<(Self, &[u8])> {
        let (signature_type, data) = data.split_at_checked(GUID_SIZE)?;
        let signature_type = uuid::Uuid::from_slice_le(signature_type).ok()?;

        let (signature_list_size, data) = data.split_at_checked(std::mem::size_of::<u32>())?;
        let signature_list_size = u32::from_le_bytes(signature_list_size.try_into().ok()?);

        let (signature_header_size, data) = data.split_at_checked(std::mem::size_of::<u32>())?;
        let signature_header_size = u32::from_le_bytes(signature_header_size.try_into().ok()?);

        let (signature_size, data) = data.split_at_checked(std::mem::size_of::<u32>())?;
        let signature_size = u32::from_le_bytes(signature_size.try_into().ok()?);

        let (_signature_header, data) =
            data.split_at_checked(signature_header_size.try_into().ok()?)?;

        let signatures_size = signature_list_size
            .checked_sub(GUID_SIZE as u32)?
            .checked_sub(3 * std::mem::size_of::<u32>() as u32)?
            .checked_sub(signature_header_size)?;
        let (signatures_data, data) = data.split_at_checked(signatures_size.try_into().ok()?)?;

        let signature_size: usize = signature_size.try_into().ok()?;

        // A signature holds at least its owner, and chunks_exact panics on zero
        if signature_size < GUID_SIZE {
            return None;
        }

        let signatures = signatures_data.chunks_exact(signature_size);

        // chunks_exact ignores a trailing partial signature
        if !signatures.remainder().is_empty() {
            return None;
        }

        let efi_signature_list = EfiSignatureList {
            signature_type,
            signatures: signatures
                .map(EfiSignatureData::try_parse)
                .collect::<Option<_>>()?,
        };

        Some((efi_signature_list, data))
    }
}

#[derive(Hash, PartialEq, Eq, Debug)]
pub(crate) struct EfiSignatureData {
    pub(crate) signature_owner: uuid::Uuid,
    pub(crate) signature_data: Vec<u8>,
}

impl EfiSignatureData {
    fn try_parse(signature: &[u8]) -> Option<Self> {
        let (signature_owner, signature_data) = signature.split_at_checked(GUID_SIZE)?;

        Some(EfiSignatureData {
            signature_owner: uuid::Uuid::from_slice_le(signature_owner).ok()?,
            signature_data: signature_data.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: uuid::Uuid = uuid::uuid!("12345678-9abc-def0-1122-334455667788");
    const EFI_CERT_X509_GUID: uuid::Uuid = uuid::uuid!("a5c059a1-94e4-4aa7-87b5-ab155c2bf072");
    const EFI_CERT_SHA256_GUID: uuid::Uuid = uuid::uuid!("c1c41626-504c-4092-aca9-41f936934328");

    const SIGNATURE_LIST_SIZE_OFFSET: usize = GUID_SIZE;
    const SIGNATURE_SIZE_OFFSET: usize = GUID_SIZE + 2 * std::mem::size_of::<u32>();

    /// Serializes an EFI_SIGNATURE_LIST of equally-sized signatures
    fn signature_list(signature_type: uuid::Uuid, signatures: &[&[u8]], header: &[u8]) -> Vec<u8> {
        let signature_size = GUID_SIZE + signatures.first().map_or(0, |signature| signature.len());
        let signature_list_size = GUID_SIZE
            + 3 * std::mem::size_of::<u32>()
            + header.len()
            + signatures.len() * signature_size;

        let mut buffer = signature_type.to_bytes_le().to_vec();
        for size in [signature_list_size, header.len(), signature_size] {
            buffer.extend_from_slice(&(size as u32).to_le_bytes());
        }
        buffer.extend_from_slice(header);
        for signature in signatures {
            assert_eq!(GUID_SIZE + signature.len(), signature_size);
            buffer.extend_from_slice(&OWNER.to_bytes_le());
            buffer.extend_from_slice(signature);
        }
        buffer
    }

    fn set_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + std::mem::size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn parses_no_lists_from_empty_data() {
        assert!(try_from(&[]).expect("parse").is_empty());
    }

    /// Written out from the UEFI specification, independent of the fixture helper
    #[test]
    fn parses_lists_in_the_specified_layout() {
        #[rustfmt::skip]
        const DATA: &[u8] = &[
            // SignatureType: EFI_CERT_SHA256_GUID, c1c41626-504c-4092-aca9-41f936934328
            0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40,
            0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28,
            // SignatureListSize: 28 + 2 + 48
            0x4e, 0x00, 0x00, 0x00,
            // SignatureHeaderSize
            0x02, 0x00, 0x00, 0x00,
            // SignatureSize: SignatureOwner and SHA-256 digest, 16 + 32
            0x30, 0x00, 0x00, 0x00,
            // SignatureHeader
            0xee, 0xff,
            // SignatureOwner: 77fa9abd-0359-4d32-bd60-28f4e78f784b
            0xbd, 0x9a, 0xfa, 0x77, 0x59, 0x03, 0x32, 0x4d,
            0xbd, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b,
            // SignatureData
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            // SignatureType: EFI_CERT_X509_GUID, a5c059a1-94e4-4aa7-87b5-ab155c2bf072
            0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
            0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
            // SignatureListSize: 28 + 0 + 2 * 20
            0x44, 0x00, 0x00, 0x00,
            // SignatureHeaderSize
            0x00, 0x00, 0x00, 0x00,
            // SignatureSize: SignatureOwner and 4 bytes of data, 16 + 4
            0x14, 0x00, 0x00, 0x00,
            // SignatureOwner: 77fa9abd-0359-4d32-bd60-28f4e78f784b
            0xbd, 0x9a, 0xfa, 0x77, 0x59, 0x03, 0x32, 0x4d,
            0xbd, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b,
            // SignatureData
            b'f', b'i', b'r', b's',
            // SignatureOwner: 77fa9abd-0359-4d32-bd60-28f4e78f784b
            0xbd, 0x9a, 0xfa, 0x77, 0x59, 0x03, 0x32, 0x4d,
            0xbd, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b,
            // SignatureData
            b'l', b'a', b's', b't',
        ];
        const SIGNATURE_OWNER: uuid::Uuid = uuid::uuid!("77fa9abd-0359-4d32-bd60-28f4e78f784b");

        let lists = try_from(DATA).expect("parse");

        assert_eq!(lists.len(), 2);
        assert_eq!(lists[0].signature_type, EFI_CERT_SHA256_GUID);
        assert_eq!(lists[0].signatures.len(), 1);
        assert_eq!(lists[0].signatures[0].signature_owner, SIGNATURE_OWNER);
        assert_eq!(
            lists[0].signatures[0].signature_data,
            (0u8..32).collect::<Vec<_>>()
        );
        assert_eq!(lists[1].signature_type, EFI_CERT_X509_GUID);
        assert_eq!(lists[1].signatures.len(), 2);
        assert_eq!(lists[1].signatures[0].signature_owner, SIGNATURE_OWNER);
        assert_eq!(lists[1].signatures[0].signature_data, b"firs");
        assert_eq!(lists[1].signatures[1].signature_data, b"last");
    }

    #[test]
    fn rejects_every_truncation() {
        let first = signature_list(EFI_CERT_X509_GUID, &[b"aaaa", b"bbbb"], b"header");
        let mut data = first.clone();
        data.extend(signature_list(EFI_CERT_SHA256_GUID, &[b"cccc"], &[]));

        for length in 1..data.len() {
            // The end of the first list is a valid database
            if length != first.len() {
                assert!(try_from(&data[..length]).is_none(), "{length} bytes");
            }
        }
    }

    #[test]
    fn rejects_a_signature_list_size_smaller_than_its_headers() {
        const HEADER: &[u8] = b"header";
        const FIXED_HEADER_SIZE: u32 = GUID_SIZE as u32 + 3 * std::mem::size_of::<u32>() as u32;

        // One byte short of the type, the fixed header and the signature header, so that each
        // subtraction underflows in turn
        for (header, signature_list_size) in [
            (&[] as &[u8], GUID_SIZE as u32 - 1),
            (&[], FIXED_HEADER_SIZE - 1),
            (HEADER, FIXED_HEADER_SIZE + HEADER.len() as u32 - 1),
        ] {
            let mut data = signature_list(EFI_CERT_X509_GUID, &[], header);

            set_u32(&mut data, SIGNATURE_LIST_SIZE_OFFSET, signature_list_size);

            assert!(
                try_from(&data).is_none(),
                "a list size of {signature_list_size}"
            );
        }
    }

    #[test]
    fn rejects_a_trailing_partial_signature() {
        let mut data = signature_list(EFI_CERT_X509_GUID, &[b"aaaa"], &[]);
        // Holds an owner, so that only the remainder check rejects it
        let partial_signature = [0u8; GUID_SIZE];
        let signature_list_size = (data.len() + partial_signature.len()) as u32;

        set_u32(&mut data, SIGNATURE_LIST_SIZE_OFFSET, signature_list_size);
        data.extend_from_slice(&partial_signature);

        assert!(try_from(&data).is_none());
    }

    #[test]
    fn requires_a_signature_size_that_holds_the_owner() {
        // Without signatures, so that only the size bound rejects it
        let mut data = signature_list(EFI_CERT_X509_GUID, &[], &[]);

        for signature_size in 0..=2 * GUID_SIZE as u32 {
            set_u32(&mut data, SIGNATURE_SIZE_OFFSET, signature_size);

            assert_eq!(
                try_from(&data).is_some(),
                signature_size >= GUID_SIZE as u32,
                "a signature size of {signature_size}"
            );
        }
    }
}
