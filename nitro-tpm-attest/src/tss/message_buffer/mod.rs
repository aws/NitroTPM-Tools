// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod nv_read_write;

use super::ContextExtension as _;
use aws_nitro_enclaves_nsm_api::api as nsm_api;
use nv_read_write::OpenNvIndex;

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("could not find free NV index handle")]
    NvIndexHandleCapacity,
    #[error(transparent)]
    Tss(#[from] tss_esapi::Error),
    #[error(transparent)]
    Serialization(ciborium::ser::Error<std::io::Error>),
    #[error(transparent)]
    Deserialization(ciborium::de::Error<std::io::Error>),
    #[error(transparent)]
    AwsLc(#[from] aws_lc_rs::error::Unspecified),
    #[error(transparent)]
    Io(std::io::Error),
}

// An NV read or write reports a TSS failure as an I/O error, also inside ciborium's Io variant.
// These three conversions unwrap it to Error::Tss.
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        error
            .downcast::<tss_esapi::Error>()
            .map_or_else(Self::Io, Self::Tss)
    }
}

impl From<ciborium::ser::Error<std::io::Error>> for Error {
    fn from(error: ciborium::ser::Error<std::io::Error>) -> Self {
        match error {
            ciborium::ser::Error::Io(error) => error.into(),
            error => Self::Serialization(error),
        }
    }
}

impl From<ciborium::de::Error<std::io::Error>> for Error {
    fn from(error: ciborium::de::Error<std::io::Error>) -> Self {
        match error {
            ciborium::de::Error::Io(error) => error.into(),
            error => Self::Deserialization(error),
        }
    }
}

pub(crate) struct MessageBuffer<'a> {
    context: &'a mut tss_esapi::Context,
    nv_index: Option<(
        // the raw handle the vendor command needs
        tss_esapi::handles::NvIndexTpmHandle,
        // the open index that reads and writes through the resolved handle it holds
        OpenNvIndex,
    )>,
    nv_index_auth: tss_esapi::structures::Auth,
}

impl<'a> MessageBuffer<'a> {
    /// Defines an input/output message buffer and writes the NSM request into it
    pub(crate) fn from_request(
        context: &'a mut tss_esapi::Context,
        nsm_request: &nsm_api::Request,
    ) -> Result<Self, Error> {
        // The plain attestation document (without any optional parameters) will be almost 5 KiB and
        // the optional parameters are each limited to 1 KiB
        const SIZE: usize = 8192;

        let mut nv_index_auth = vec![0u8; tss_esapi::structures::Auth::MAX_SIZE];

        aws_lc_rs::rand::fill(&mut nv_index_auth)?;

        let nv_index_auth = tss_esapi::structures::Auth::try_from(nv_index_auth)?;

        let nv_index_tpm_handle = tss_esapi::handles::NvIndexTpmHandle::try_from(
            context
                .find_free_handle(
                    tss_esapi::constants::tss::TPM2_NV_INDEX_FIRST,
                    tss_esapi::constants::tss::TPM2_NV_INDEX_LAST,
                )?
                .ok_or(Error::NvIndexHandleCapacity)?,
        )?;

        let nv_index_attributes = tss_esapi::attributes::nv_index::NvIndexAttributes::builder()
            .with_auth_read(true)
            .with_auth_write(true)
            .build()?;
        let nv_public = tss_esapi::structures::NvPublic::builder()
            .with_nv_index(nv_index_tpm_handle)
            .with_index_name_algorithm(
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha512,
            )
            .with_index_attributes(nv_index_attributes)
            .with_data_area_size(SIZE)
            .build()?;

        // The largest chunk a read or write may carry: what the TPM reports, but no more than
        // MaxNvBuffer holds
        let buffer_size = context
            .get_tpm_property(tss_esapi::constants::property_tag::PropertyTag::NvBufferMax)?
            .map(usize::try_from)
            .transpose()
            .map_err(|_| {
                tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::WrongValueFromTpm)
            })?
            .unwrap_or(tss_esapi::structures::MaxNvBuffer::MAX_SIZE)
            .min(tss_esapi::structures::MaxNvBuffer::MAX_SIZE);

        let nv_index_handle = context.nv_define_space(
            tss_esapi::interface_types::resource_handles::Provision::Owner,
            Some(nv_index_auth.clone()),
            nv_public,
        )?;

        // Constructed before the write, so a failure there undefines the index on drop
        let message_buffer = Self {
            context,
            nv_index: Some((
                nv_index_tpm_handle,
                OpenNvIndex::new(nv_index_handle, buffer_size, SIZE),
            )),
            nv_index_auth,
        };

        {
            let open_nv_index = &message_buffer
                .nv_index
                .as_ref()
                .expect("NV index should be set until it is undefined")
                .1;
            let mut writer =
                std::io::BufWriter::new(open_nv_index.reader_writer(message_buffer.context));

            ciborium::into_writer(nsm_request, &mut writer)?;
            // BufWriter's Drop swallows errors, so its buffer is flushed explicitly
            std::io::Write::flush(&mut writer)?;
        }

        Ok(message_buffer)
    }

    /// Reads the NSM response from the message buffer and undefines the buffer afterwards
    pub(crate) fn into_response(mut self) -> Result<nsm_api::Response, Error> {
        let response = self.response();
        let undefined = self.undefine();
        // The response error is more telling than a failure to undefine
        let response = response?;

        undefined?;

        Ok(response)
    }

    fn response(&mut self) -> Result<nsm_api::Response, Error> {
        let open_nv_index = &self
            .nv_index
            .as_ref()
            .expect("NV index should be set until it is undefined")
            .1;

        Ok(ciborium::from_reader(std::io::BufReader::new(
            open_nv_index.reader_writer(self.context),
        ))?)
    }

    pub(crate) fn index(&self) -> tss_esapi::handles::NvIndexTpmHandle {
        self.nv_index
            .as_ref()
            .expect("NV index should be set until it is undefined")
            .0
    }

    pub(crate) fn auth(&self) -> &tss_esapi::structures::Auth {
        &self.nv_index_auth
    }

    /// Undefines the message buffer, unless it is undefined already
    fn undefine(&mut self) -> Result<(), Error> {
        let Some((_, open_nv_index)) = self.nv_index.take() else {
            return Ok(());
        };

        Ok(self.context.nv_undefine_space(
            tss_esapi::interface_types::resource_handles::Provision::Owner,
            open_nv_index.into_nv_index_handle(),
        )?)
    }
}

impl Drop for MessageBuffer<'_> {
    fn drop(&mut self) {
        // Only cleans up when into_response was not called, which means an error is already
        // propagating
        let _ = self.undefine();
    }
}
