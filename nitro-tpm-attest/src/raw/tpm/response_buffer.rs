// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::Error;

pub(super) struct Parser<'a> {
    data: &'a [u8],
}

impl<'a> Parser<'a> {
    pub(super) fn from(data: &'a mut [u8]) -> Result<Self, Error> {
        const TPM_HEADER_SIZE: usize = 10;
        const TPM_RESPONSE_CODE_OFFSET: usize = 6;

        let (header, data) = data
            .split_at_checked(TPM_HEADER_SIZE)
            .ok_or(Error::InvalidTpmResponse)?;
        let response_code = header
            .get(TPM_RESPONSE_CODE_OFFSET..TPM_RESPONSE_CODE_OFFSET + std::mem::size_of::<u32>())
            .ok_or(Error::InvalidTpmResponse)?
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| Error::InvalidTpmResponse)?;

        if response_code != 0 {
            return Err(Error::TpmErrorResponse(
                tss_esapi::constants::response_code::Tss2ResponseCode::from(response_code),
            ));
        }

        Ok(Self { data })
    }

    pub(super) fn read_sized_buffer(&mut self) -> Result<&'a [u8], Error> {
        let size = self.read_u16()?;
        let (value, rest) = self
            .data
            .split_at_checked(size.into())
            .ok_or(Error::InvalidTpmResponse)?;

        self.data = rest;

        Ok(value)
    }

    pub(super) fn read_u16(&mut self) -> Result<u16, Error> {
        let (value, rest) = self
            .data
            .split_at_checked(std::mem::size_of::<u16>())
            .ok_or(Error::InvalidTpmResponse)?;

        self.data = rest;

        value
            .try_into()
            .map(u16::from_be_bytes)
            .map_err(|_| Error::InvalidTpmResponse)
    }

    pub(super) fn read_u32(&mut self) -> Result<u32, Error> {
        let (value, rest) = self
            .data
            .split_at_checked(std::mem::size_of::<u32>())
            .ok_or(Error::InvalidTpmResponse)?;

        self.data = rest;

        value
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| Error::InvalidTpmResponse)
    }
}
