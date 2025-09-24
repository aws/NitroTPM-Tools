// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod command_buffer;
mod response_buffer;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid TPM request")]
    InvalidTpmRequest,
    #[error("invalid TPM response")]
    InvalidTpmResponse,
    #[error("TPM error response: {0}")]
    TpmErrorResponse(tss_esapi::constants::response_code::Tss2ResponseCode),
    #[error(transparent)]
    Tss(#[from] tss_esapi::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub(super) const TPM2_VENDOR_AWS_NSM_REQUEST: u32 = 0x20000001;

pub(crate) struct Tpm {
    device: std::fs::File,
}

impl Tpm {
    pub(crate) fn new(device_path: &std::path::Path) -> Result<Self, Error> {
        let device = std::fs::File::options()
            .read(true)
            .write(true)
            .open(device_path)?;

        Ok(Self { device })
    }

    pub(super) fn nsm_request(
        &mut self,
        nv_index: tss_esapi::handles::NvIndexTpmHandle,
        auth_area: &[u8],
    ) -> Result<(), Error> {
        let command_buffer = command_buffer::Builder::new(
            tss_esapi::constants::tss::TPM2_ST_SESSIONS,
            TPM2_VENDOR_AWS_NSM_REQUEST,
        )
        // Handles
        .add_u32(nv_index) // NV auth
        .add_u32(nv_index) // NV index
        // Auth area
        .add_auth_area(auth_area)
        .build();

        response_buffer::Parser::from(&mut self.send_command_buffer(&command_buffer)?)?;

        Ok(())
    }

    pub(super) fn start_auth_session(
        &mut self,
        encrypted_salt: Option<(
            tss_esapi::handles::TpmHandle,
            &tss_esapi::structures::EncryptedSecret,
        )>,
        bind_handle: Option<tss_esapi::handles::TpmHandle>,
        nonce_caller: &tss_esapi::structures::Nonce,
        session_type: tss_esapi::constants::session_type::SessionType,
        symmetric_definition: tss_esapi::structures::SymmetricDefinition,
        hash_alg: tss_esapi::interface_types::algorithm::HashingAlgorithm,
    ) -> Result<(tss_esapi::handles::TpmHandle, tss_esapi::structures::Nonce), Error> {
        let (salt_key_handle, encrypted_salt) = encrypted_salt.unzip();
        let encrypted_salt = match encrypted_salt {
            Some(encrypted_salt) => encrypted_salt,
            None => &Default::default(),
        };
        let symmetric_definition =
            tss_esapi::tss2_esys::TPMT_SYM_DEF::try_from(symmetric_definition)?;

        if nonce_caller.len() < 16 {
            return Err(Error::InvalidTpmRequest);
        }

        if symmetric_definition.algorithm != tss_esapi::constants::tss::TPM2_ALG_NULL {
            unimplemented!();
        }

        let command_buffer = command_buffer::Builder::new(
            tss_esapi::constants::tss::TPM2_ST_NO_SESSIONS,
            tss_esapi::constants::tss::TPM2_CC_StartAuthSession,
        )
        // Handles
        .add_u32(salt_key_handle.map_or(tss_esapi::constants::tss::TPM2_RH_NULL, Into::<u32>::into))
        .add_u32(bind_handle.map_or(tss_esapi::constants::tss::TPM2_RH_NULL, Into::<u32>::into))
        // Parameters
        .add_sized_buffer(nonce_caller.as_slice())
        .add_sized_buffer(encrypted_salt.as_slice())
        .add_u8(session_type)
        .add_u16(symmetric_definition.algorithm)
        .add_u16(tss_esapi::tss2_esys::TPMI_ALG_HASH::from(hash_alg))
        .build();

        let mut response = self.send_command_buffer(&command_buffer)?;
        let mut response_parser = response_buffer::Parser::from(&mut response)?;

        let session_handle = response_parser
            .read_u32()?
            .try_into()
            .map_err(|_| Error::InvalidTpmResponse)?;
        let nonce = response_parser
            .read_sized_buffer()?
            .try_into()
            .map_err(|_| Error::InvalidTpmResponse)?;

        Ok((session_handle, nonce))
    }

    pub(super) fn flush_context(
        &mut self,
        flush_handle: tss_esapi::handles::TpmHandle,
    ) -> Result<(), Error> {
        let command_buffer = command_buffer::Builder::new(
            tss_esapi::constants::tss::TPM2_ST_NO_SESSIONS,
            tss_esapi::constants::tss::TPM2_CC_FlushContext,
        )
        // Handles
        .add_u32(flush_handle)
        .build();

        response_buffer::Parser::from(&mut self.send_command_buffer(&command_buffer)?)?;

        Ok(())
    }

    fn send_command_buffer(&mut self, command_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        std::io::Write::write_all(&mut self.device, command_buffer)?;

        let mut response = Vec::new();

        std::io::Read::read_to_end(&mut self.device, &mut response)?;

        Ok(response)
    }
}
