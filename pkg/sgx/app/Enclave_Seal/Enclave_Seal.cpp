/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave_Seal_t.h"

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"

uint32_t get_sealed_data_size(uint32_t unsealed_data_size, uint32_t unsealed_mac_text_size)
{
    return sgx_calc_sealed_data_size(unsealed_mac_text_size, unsealed_data_size);
}

sgx_status_t seal_data(const uint8_t *unsealed_data, uint32_t unsealed_data_size, const uint8_t *unsealed_mac_text, uint32_t unsealed_mac_text_size, uint8_t *sealed_data, uint32_t sealed_data_size)
{
    uint32_t expected_sealed_data_size = sgx_calc_sealed_data_size(unsealed_mac_text_size, unsealed_data_size);
    if (expected_sealed_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (expected_sealed_data_size > sealed_data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(expected_sealed_data_size);
    if(temp_sealed_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    sgx_status_t err = sgx_seal_data(unsealed_mac_text_size, unsealed_mac_text, unsealed_data_size, unsealed_data, expected_sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);
    if (err == SGX_SUCCESS)
    {
        // Copy the sealed data to outside buffer
        memcpy(sealed_data, temp_sealed_buf, expected_sealed_data_size);
    }

    free(temp_sealed_buf);
    return err;
}
