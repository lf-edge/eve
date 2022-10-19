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

// App.cpp : Define the entry point for the console application.
//

#include <string.h>
#include <assert.h>
#include <fstream>
#include <thread>
#include <iostream>

#include "sgx_urts.h"
#include "Enclave_Seal_u.h"
#include "Enclave_Unseal_u.h"

#include "ErrorSupport.h"

#define ENCLAVE_NAME_SEAL "libenclave_seal.signed.so"
#define ENCLAVE_NAME_UNSEAL "libenclave_unseal.signed.so"

char aad_mac_text[BUFSIZ] = "sample-mac";



static size_t get_file_size(const char *filename)
{
    std::ifstream ifs(filename, std::ios::in | std::ios::binary);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return -1;
    }
    ifs.seekg(0, std::ios::end);
    size_t size = (size_t)ifs.tellg();
    return size;
}

static bool read_file_to_buf(const char *filename, uint8_t *buf, size_t bsize)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ifstream ifs(filename, std::ios::binary | std::ios::in);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ifs.read(reinterpret_cast<char *> (buf), bsize);
    if (ifs.fail())
    {
        std::cout << "Failed to read the file \"" << filename << "\"" << std::endl;
        return false;
    }
    return true;
}

static bool write_buf_to_file(const char *filename, const uint8_t *buf, size_t bsize, long offset)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ofstream ofs(filename, std::ios::binary | std::ios::out);
    if (!ofs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ofs.seekp(offset, std::ios::beg);
    ofs.write(reinterpret_cast<const char*>(buf), bsize);
    if (ofs.fail())
    {
        std::cout << "Failed to write the file \"" << filename << "\"" << std::endl;
        return false;
    }

    return true;
}

/* Initialize the enclave:
*   Call sgx_create_enclave to initialize an enclave instance
*/
static sgx_status_t initialize_enclave(const char* enclave_path, sgx_enclave_id_t *eid)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, NULL, NULL, eid, NULL);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    return SGX_SUCCESS;
}


static bool seal_and_save_data(char* in_file, char* out_file)
{
    sgx_enclave_id_t eid_seal = 0;
    // Load the enclave for sealing
    sgx_status_t ret = initialize_enclave(ENCLAVE_NAME_SEAL, &eid_seal);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return false;
    }

    // Read the sealed blob from the file
    size_t fsize = get_file_size(in_file);
    if (fsize == (size_t)-1)
    {
        std::cout << "Failed to get the file size of \"" << in_file << "\"" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    uint8_t *temp_buf = (uint8_t *)malloc(fsize);
    if(temp_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    if (read_file_to_buf(in_file, temp_buf, fsize) == false)
    {
        std::cout << "Failed to read the sealed data blob from \"" << in_file << "\"" << std::endl;
        free(temp_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    // Get the sealed data size
    uint32_t sealed_data_size = 0;
    ret = get_sealed_data_size(eid_seal, &sealed_data_size, (uint32_t)fsize, (uint32_t)strlen(aad_mac_text));
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(temp_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    else if(sealed_data_size == UINT32_MAX)
    {
        free(temp_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if(temp_sealed_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    sgx_status_t retval;
    ret = seal_data(eid_seal, &retval, temp_buf, (uint32_t)fsize, (const uint8_t *)aad_mac_text, (uint32_t)strlen(aad_mac_text), temp_sealed_buf, sealed_data_size);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(temp_buf);
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    else if( retval != SGX_SUCCESS)
    {
        ret_error_support(retval);
        free(temp_buf);
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    free(temp_buf);

    // Save the sealed blob
    if (write_buf_to_file(out_file, temp_sealed_buf, sealed_data_size, 0) == false)
    {
        std::cout << "Failed to save the sealed data blob to \"" << out_file << "\"" << std::endl;
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    free(temp_sealed_buf);
    sgx_destroy_enclave(eid_seal);

    std::cout << "Sealing data succeeded." << std::endl;
    return true;

}

static bool read_and_unseal_data(char* in_file, char* out_file)
{
    sgx_enclave_id_t eid_unseal = 0;
    // Load the enclave for unsealing
    sgx_status_t ret = initialize_enclave(ENCLAVE_NAME_UNSEAL, &eid_unseal);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return false;
    }
    // Read the sealed blob from the file
    size_t fsize = get_file_size(in_file);
    if (fsize == (size_t)-1)
    {
        std::cout << "Failed to get the file size of \"" << in_file << "\"" << std::endl;
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    uint8_t *temp_buf = (uint8_t *)malloc(fsize);
    if(temp_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    if (read_file_to_buf(in_file, temp_buf, fsize) == false)
    {
        std::cout << "Failed to read the sealed data blob from \"" << in_file << "\"" << std::endl;
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    uint32_t temp_unsealed_buf_size = 0;
    ret = get_unsealed_data_size(eid_unseal, &temp_unsealed_buf_size, temp_buf, (uint32_t)fsize);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    else if(temp_unsealed_buf_size == UINT32_MAX)
    {
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }


    uint32_t temp_mac_buf_size = 0;
    ret = get_unsealed_mac_size(eid_unseal, &temp_mac_buf_size, temp_buf, (uint32_t)fsize);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    else if(temp_mac_buf_size == UINT32_MAX)
    {
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    uint8_t *temp_unsealed_buf = (uint8_t *)malloc(temp_unsealed_buf_size);
    if(temp_unsealed_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    uint8_t *temp_mac_buf = (uint8_t *)malloc(temp_mac_buf_size);
    if(temp_mac_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        free(temp_buf);
        free(temp_unsealed_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    // Unseal the sealed blob
    sgx_status_t retval;
    ret = unseal_data(eid_unseal, &retval, temp_buf, (uint32_t)fsize, temp_unsealed_buf, temp_unsealed_buf_size, temp_mac_buf, temp_mac_buf_size);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(temp_unsealed_buf);
        free(temp_mac_buf);
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    else if(retval != SGX_SUCCESS)
    {
        ret_error_support(retval);
        free(temp_unsealed_buf);
        free(temp_mac_buf);
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    free(temp_buf);

    if (memcmp(temp_mac_buf, aad_mac_text, temp_mac_buf_size))
    {
        std::cout << "MAC is not correct" << std::endl;
        free(temp_unsealed_buf);
        free(temp_mac_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    free(temp_mac_buf);

    // Save the sealed blob
    if (write_buf_to_file(out_file, temp_unsealed_buf, temp_unsealed_buf_size, 0) == false)
    {
        std::cout << "Failed to save the sealed data blob to \"" << out_file << "\"" << std::endl;
        free(temp_unsealed_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    free(temp_unsealed_buf);
    sgx_destroy_enclave(eid_unseal);

    std::cout << "Unseal succeeded." << std::endl;
    return true;
}


int main(int argc, char* argv[])
{
    if (argc != 4) {
        std::cerr << "missing arguments" << std::endl;
        std::cerr << "usage: <seal|unseal> <input file> <output file>" << std::endl;
        return EXIT_FAILURE;
    }
    if (strcmp(argv[1], "seal") == 0) {
        // Enclave_Seal: seal the secret and save the data blob to a file
        if (seal_and_save_data(argv[2], argv[3]) == false)
        {
            std::cerr << "Failed to seal the secret and save it to a file." << std::endl;
            return EXIT_FAILURE;
        }
    }else{
        // Enclave_Unseal: read the data blob from the file and unseal it.
        if (read_and_unseal_data(argv[2], argv[3]) == false)
        {
            std::cerr << "Failed to unseal the data blob." << std::endl;
            return EXIT_FAILURE;
        }
    }

    return 0;
}

