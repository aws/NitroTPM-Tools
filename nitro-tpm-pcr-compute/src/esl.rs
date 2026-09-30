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

#[derive(Debug)]
pub(crate) struct EfiSignatureList {
    pub(crate) signature_type: uuid::Uuid,
    pub(crate) signatures: Vec<EfiSignatureData>,
}

impl EfiSignatureList {
    pub(crate) fn try_parse(data: &[u8]) -> Option<(Self, &[u8])> {
        let (signature_type, data) = data.split_at_checked(std::mem::size_of::<uuid::Bytes>())?;
        let signature_type = uuid::Uuid::from_slice_le(signature_type).ok()?;

        let (signature_list_size, data) = data.split_at_checked(std::mem::size_of::<u32>())?;
        let signature_list_size = u32::from_le_bytes(signature_list_size.try_into().ok()?);

        let (signature_header_size, data) = data.split_at_checked(std::mem::size_of::<u32>())?;
        let signature_header_size = u32::from_le_bytes(signature_header_size.try_into().ok()?);

        let (signature_size, data) = data.split_at_checked(std::mem::size_of::<u32>())?;
        let signature_size = u32::from_le_bytes(signature_size.try_into().ok()?);

        let (_signature_header, mut data) =
            data.split_at_checked(signature_header_size.try_into().ok()?)?;

        let signature_count = (signature_list_size
            - std::mem::size_of::<uuid::Bytes>() as u32
            - 3 * std::mem::size_of::<u32>() as u32
            - signature_header_size)
            / signature_size;
        let mut signatures = Vec::with_capacity(signature_count.try_into().ok()?);

        while !data.is_empty() {
            let (signature, remaining_data) = EfiSignatureData::try_parse(data, signature_size)?;

            signatures.push(signature);
            data = remaining_data;
        }

        let efi_signature_list = EfiSignatureList {
            signature_type,
            signatures,
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
    fn try_parse(data: &[u8], signature_size: u32) -> Option<(Self, &[u8])> {
        let (signature_owner, data) = data.split_at_checked(16)?;
        let signature_owner = uuid::Uuid::from_slice_le(signature_owner).ok()?;

        let signature_data_size = signature_size.checked_sub(16)?.try_into().ok()?;
        let (signature_data, data) = data.split_at_checked(signature_data_size)?;
        let signature_data = signature_data.to_vec();

        let efi_signature_data = EfiSignatureData {
            signature_owner,
            signature_data,
        };

        Some((efi_signature_data, data))
    }
}
