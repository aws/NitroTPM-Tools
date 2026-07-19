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
