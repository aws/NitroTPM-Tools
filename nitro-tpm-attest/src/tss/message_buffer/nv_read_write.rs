// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reads and writes an already-open NV index
//!
//! tss_esapi's NvReaderWriter cannot be used here: as its documentation warns, dropping it may
//! close any ESYS handle to the index, and ESYS hands out a single handle per index, so that
//! includes the one the message buffer holds.

/// An NV index already resolved for reading and writing, so the message buffer is driven through
/// the handle it holds instead of reopened, which reads the index public afresh each time
pub(super) struct OpenNvIndex {
    nv_index_handle: tss_esapi::handles::NvIndexHandle,
    buffer_size: usize,
    data_size: usize,
}

impl OpenNvIndex {
    pub(super) fn new(
        nv_index_handle: tss_esapi::handles::NvIndexHandle,
        buffer_size: usize,
        data_size: usize,
    ) -> Self {
        Self {
            nv_index_handle,
            buffer_size,
            data_size,
        }
    }

    /// Consumes the open index into its resolved handle, to undefine the index it is done with
    pub(super) fn into_nv_index_handle(self) -> tss_esapi::handles::NvIndexHandle {
        self.nv_index_handle
    }

    /// A reader/writer over the context whose authorization session carries the transfer; the index
    /// is already resolved, so nothing is read from the TPM to hand one out
    pub(super) fn reader_writer<'a>(
        &'a self,
        context: &'a mut tss_esapi::Context,
    ) -> NvIndexReaderWriter<'a> {
        NvIndexReaderWriter {
            context,
            open_nv_index: self,
            offset: 0,
        }
    }
}

/// Reads and writes an [`OpenNvIndex`] in the chunks the TPM's maximum NV buffer allows, bound to a
/// context for the span of one operation
///
/// Mirrors the chunking of tss_esapi's NvReaderWriter, over a handle held across operations rather
/// than one NvOpenOptions::open resolves and closes each time.
pub(super) struct NvIndexReaderWriter<'a> {
    context: &'a mut tss_esapi::Context,
    open_nv_index: &'a OpenNvIndex,
    offset: usize,
}

impl NvIndexReaderWriter<'_> {
    /// The index authorizes its own reads and writes
    fn auth_handle(&self) -> tss_esapi::interface_types::resource_handles::NvAuth {
        tss_esapi::interface_types::resource_handles::NvAuth::NvIndex(
            self.open_nv_index.nv_index_handle,
        )
    }

    /// Size of the next chunk: what the buffer holds, capped by what is left and by the largest
    /// transfer the TPM accepts; zero once the whole data area has been consumed
    fn chunk_size(&self, buffer_len: usize) -> usize {
        buffer_len
            .min(self.open_nv_index.data_size.saturating_sub(self.offset))
            .min(self.open_nv_index.buffer_size)
    }
}

impl std::io::Read for NvIndexReaderWriter<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let size = self.chunk_size(buffer.len());

        if size == 0 {
            return Ok(0);
        }

        let read = self
            .context
            .nv_read(
                self.auth_handle(),
                self.open_nv_index.nv_index_handle,
                size as u16,
                self.offset as u16,
            )
            .map_err(std::io::Error::other)?;

        if read.len() > size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the TPM returned more than the requested NV read size",
            ));
        }

        buffer[..read.len()].copy_from_slice(&read);
        self.offset += read.len();

        Ok(read.len())
    }
}

impl std::io::Write for NvIndexReaderWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let size = self.chunk_size(buffer.len());

        if size == 0 {
            return Ok(0);
        }

        let data = buffer[..size].try_into().map_err(std::io::Error::other)?;

        self.context
            .nv_write(
                self.auth_handle(),
                self.open_nv_index.nv_index_handle,
                data,
                self.offset as u16,
            )
            .map_err(std::io::Error::other)?;

        self.offset += size;

        Ok(size)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
