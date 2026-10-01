// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod nv_read_write;

use super::ContextExtension as _;
use aws_nitro_enclaves_nsm_api::api as nsm_api;
use nv_read_write::OpenNvIndex;

/// Rounded up size of a plain attestation document
const BASE_SIZE: usize = 5 * 1024;

/// Largest optional parameter the NSM accepts
pub(crate) const PARAMETER_MAX_SIZE: usize = 1024;

/// Largest message buffer any request can need, which a TPM is rejected against so that one unable
/// to answer every request is reported up front
///
/// Comes to the 8192 bytes that are also the largest an NV index may be on a NitroTPM.
pub(crate) const MAX_SIZE: usize = BASE_SIZE + 3 * PARAMETER_MAX_SIZE;

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("could not find free NV index handle")]
    NvIndexHandleCapacity,
    #[error(transparent)]
    Tss(#[from] tss_esapi::Error),
    #[error(transparent)]
    Serialization(#[from] ciborium::ser::Error<std::io::Error>),
    #[error(transparent)]
    Deserialization(#[from] ciborium::de::Error<std::io::Error>),
    #[error(transparent)]
    AwsLc(#[from] aws_lc_rs::error::Unspecified),
    #[error(transparent)]
    Io(#[from] std::io::Error),
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
        let mut nv_index_auth = vec![0u8; tss_esapi::structures::Auth::MAX_SIZE];

        aws_lc_rs::rand::fill(&mut nv_index_auth)?;

        let nv_index_auth = tss_esapi::structures::Auth::try_from(nv_index_auth)?;

        let data_size = size(nsm_request);
        // The largest chunk a read or write may carry
        let buffer_size = context
            .get_tpm_property(tss_esapi::constants::property_tag::PropertyTag::NvBufferMax)?
            .map(usize::try_from)
            .transpose()
            .map_err(|_| {
                tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::WrongValueFromTpm)
            })?
            .unwrap_or(tss_esapi::structures::MaxNvBuffer::MAX_SIZE);

        let (nv_index_tpm_handle, nv_index_handle) =
            reserve_nv_index(context, &nv_index_auth, data_size)?;

        // Constructed before the write, so a failure there undefines the index on drop
        let message_buffer = Self {
            context,
            nv_index: Some((
                nv_index_tpm_handle,
                OpenNvIndex::new(nv_index_handle, buffer_size, data_size),
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

/// Size a message buffer needs for the request it carries and the response overwriting it
///
/// The response is the larger of the two, and the NSM echoes every optional parameter into it, so
/// each one is charged on top of the base. Sizing a request below the maximum is what admits more
/// of them at a time, because the TPM has little NV memory left for indices.
fn size(nsm_request: &nsm_api::Request) -> usize {
    let nsm_api::Request::Attestation {
        user_data,
        nonce,
        public_key,
    } = nsm_request
    else {
        unreachable!("the crate sends only attestation requests");
    };

    [user_data, nonce, public_key]
        .into_iter()
        .flatten()
        .map(|parameter| parameter.len())
        .fold(BASE_SIZE, |size, parameter| size.saturating_add(parameter))
}

/// Reserves an NV index, retrying behind any handle another process takes first
fn reserve_nv_index(
    context: &mut tss_esapi::Context,
    nv_index_auth: &tss_esapi::structures::Auth,
    size: usize,
) -> Result<
    (
        tss_esapi::handles::NvIndexTpmHandle,
        tss_esapi::handles::NvIndexHandle,
    ),
    Error,
> {
    let mut start_handle = tss_esapi::constants::tss::TPM2_NV_INDEX_FIRST;

    loop {
        let nv_index_tpm_handle = tss_esapi::handles::NvIndexTpmHandle::try_from(
            context
                .find_free_handle(start_handle, tss_esapi::constants::tss::TPM2_NV_INDEX_LAST)?
                .ok_or(Error::NvIndexHandleCapacity)?,
        )?;

        if let Some(nv_index_handle) =
            define_nv_index(context, nv_index_tpm_handle, nv_index_auth, size)?
        {
            return Ok((nv_index_tpm_handle, nv_index_handle));
        }

        start_handle = u32::from(nv_index_tpm_handle)
            .checked_add(1)
            .ok_or(Error::NvIndexHandleCapacity)?;
    }
}

/// Defines the message buffer's NV index at the given handle and returns the handle it resolved to,
/// or None when another process has already taken the handle
///
/// Reserving the handle is the definition itself, so that a handle another process defined first is
/// never mistaken for one of ours.
fn define_nv_index(
    context: &mut tss_esapi::Context,
    nv_index_tpm_handle: tss_esapi::handles::NvIndexTpmHandle,
    nv_index_auth: &tss_esapi::structures::Auth,
    size: usize,
) -> Result<Option<tss_esapi::handles::NvIndexHandle>, Error> {
    let nv_public = tss_esapi::structures::NvPublic::builder()
        .with_nv_index(nv_index_tpm_handle)
        .with_index_name_algorithm(tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha512)
        .with_index_attributes(
            tss_esapi::attributes::nv_index::NvIndexAttributes::builder()
                .with_auth_read(true)
                .with_auth_write(true)
                .build()?,
        )
        .with_data_area_size(size)
        .build()?;

    match context.nv_define_space(
        tss_esapi::interface_types::resource_handles::Provision::Owner,
        Some(nv_index_auth.clone()),
        nv_public,
    ) {
        Ok(nv_index_handle) => Ok(Some(nv_index_handle)),
        Err(tss_esapi::Error::Tss2Error(response_code))
            if response_code.kind()
                == Some(tss_esapi::constants::response_code::Tss2ResponseCodeKind::NvDefined) =>
        {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}
