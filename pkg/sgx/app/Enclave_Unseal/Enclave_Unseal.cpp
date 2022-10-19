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

#include "Enclave_Unseal_t.h"

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"


uint32_t get_unsealed_data_size(const uint8_t *sealed_blob, uint32_t sealed_data_size)
{
    (void)sealed_data_size;
    return sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
}

uint32_t get_unsealed_mac_size(const uint8_t *sealed_blob, uint32_t sealed_data_size)
{
    (void)sealed_data_size;
    return sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
}

sgx_status_t unseal_data(const uint8_t *sealed_blob, uint32_t sealed_data_size, uint8_t *unsealed_blob, uint32_t unsealed_data_size, uint8_t *unsealed_mac_text, uint32_t unsealed_mac_text_size)
{
    (void)sealed_data_size;
    uint32_t expected_unsealed_mac_text_size = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint32_t expected_unsealed_data_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    if ((expected_unsealed_mac_text_size == UINT32_MAX) || (expected_unsealed_data_size == UINT32_MAX))
        return SGX_ERROR_UNEXPECTED;
    if ((expected_unsealed_mac_text_size > unsealed_mac_text_size) || (expected_unsealed_data_size > unsealed_data_size))
        return SGX_ERROR_UNEXPECTED;

    uint8_t *de_mac_text =(uint8_t *)malloc(expected_unsealed_mac_text_size);
    if(de_mac_text == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    uint8_t *decrypt_data = (uint8_t *)malloc(expected_unsealed_data_size);
    if(decrypt_data == NULL)
    {
        free(de_mac_text);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, de_mac_text, &expected_unsealed_mac_text_size, decrypt_data, &expected_unsealed_data_size);
    if (ret != SGX_SUCCESS)
    {
        free(de_mac_text);
        free(decrypt_data);
        return ret;
    }
    memcpy(unsealed_blob, decrypt_data, expected_unsealed_data_size);
    memcpy(unsealed_mac_text, de_mac_text, expected_unsealed_mac_text_size);
    free(de_mac_text);
    free(decrypt_data);
    return ret;
}
