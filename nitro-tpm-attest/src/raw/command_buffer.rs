// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub(super) struct Builder {
    buffer: Vec<u8>,
}

impl Builder {
    pub(super) fn new(session_type: u16, command_code: u32) -> Self {
        let mut buffer = Vec::new();

        // Header
        buffer.extend_from_slice(&session_type.to_be_bytes());
        buffer.extend_from_slice(&0u32.to_be_bytes()); // size placeholder
        buffer.extend_from_slice(&command_code.to_be_bytes());

        Self { buffer }
    }

    pub(super) fn add_auth_area(mut self, data: &[u8]) -> Self {
        self.buffer
            .extend_from_slice(&(data.len() as u32).to_be_bytes());
        self.buffer.extend_from_slice(data);

        self
    }

    pub(super) fn add_u32(mut self, value: impl Into<u32>) -> Self {
        self.buffer.extend_from_slice(&value.into().to_be_bytes());

        self
    }

    pub(super) fn build(mut self) -> Vec<u8> {
        const TPM_COMMAND_SIZE_OFFSET: usize = 2;

        let command_size = self.buffer.len() as u32;

        self.buffer[TPM_COMMAND_SIZE_OFFSET..TPM_COMMAND_SIZE_OFFSET + std::mem::size_of::<u32>()]
            .copy_from_slice(&command_size.to_be_bytes());

        self.buffer
    }
}
