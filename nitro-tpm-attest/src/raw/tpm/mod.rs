// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod command_buffer;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid TPM response")]
    InvalidTpmResponse,
    #[error("TPM error response: {0}")]
    TpmErrorResponse(tss_esapi::constants::response_code::Tss2ResponseCode),
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
        auth: &tss_esapi::structures::Auth,
    ) -> Result<(), Error> {
        // 19.4 Password Authorizations
        let nonce_caller = tss_esapi::structures::Nonce::default();
        let (session_attributes, _) =
            tss_esapi::attributes::session::SessionAttributes::builder().build();
        let session_attributes = tss_esapi::tss2_esys::TPMA_SESSION::from(session_attributes);
        let auth_area = [
            tss_esapi::constants::tss::TPM2_RS_PW
                .to_be_bytes()
                .as_slice(),
            &(nonce_caller.len() as u16).to_be_bytes(),
            &nonce_caller,
            &session_attributes.to_be_bytes(),
            &(auth.len() as u16).to_be_bytes(),
            auth,
        ]
        .concat();

        let command_buffer = command_buffer::Builder::new(
            tss_esapi::constants::tss::TPM2_ST_SESSIONS,
            TPM2_VENDOR_AWS_NSM_REQUEST,
        )
        // Handles
        .add_u32(nv_index) // NV auth
        .add_u32(nv_index) // NV index
        // Auth area
        .add_auth_area(&auth_area)
        .build();

        self.send_command_buffer(&command_buffer)?;

        Ok(())
    }

    fn send_command_buffer(&mut self, command_buffer: &[u8]) -> Result<(), Error> {
        const TPM_RESPONSE_CODE_OFFSET: usize = 6;

        std::io::Write::write_all(&mut self.device, command_buffer)?;

        let mut response = Vec::new();

        std::io::Read::read_to_end(&mut self.device, &mut response)?;

        let response_code = response
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

        Ok(())
    }
}
