/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_HARDWARE_KEYMASTER_COMMON_H
#define ANDROID_HARDWARE_KEYMASTER_COMMON_H

#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/types.h>

/**
 * The id of this module
 */
#define KEYSTORE_HARDWARE_MODULE_ID "keystore"

#define KEYSTORE_KEYMASTER "keymaster"

/**
 * Asymmetric key pair types.
 */
enum keymaster_keypair {
    TYPE_RSA = 1,
    TYPE_DSA = 2,
    TYPE_EC = 3,
};

/**
 * Parameters needed to generate an RSA key.
 */
struct keymaster_rsa_keygen_params {
    uint32_t modulus_size;
    uint64_t public_exponent;
};

/**
 * Parameters needed to generate a DSA key.
 */
struct keymaster_dsa_keygen_params {
    uint32_t key_size;
    uint32_t generator_len;
    uint32_t prime_p_len;
    uint32_t prime_q_len;
    const uint8_t* generator;
    const uint8_t* prime_p;
    const uint8_t* prime_q;
};

/**
 * Parameters needed to generate an EC key.
 *
 * Field size is the only parameter in version 2. The sizes correspond to these required curves:
 *
 * 192 = NIST P-192
 * 224 = NIST P-224
 * 256 = NIST P-256
 * 384 = NIST P-384
 * 521 = NIST P-521
 *
 * The parameters for these curves are available at: http://www.nsa.gov/ia/_files/nist-routines.pdf
 * in Chapter 4.
 */
struct keymaster_ec_keygen_params {
    uint32_t field_size;
};


/**
 * Digest type.
 */
enum keymaster_digest_algorithm {
    DIGEST_NONE,
};

/**
 * Type of padding used for RSA operations.
 */
enum keymaster_rsa_padding {
    PADDING_NONE,
};


struct keymaster_dsa_sign_params {
    enum keymaster_digest_algorithm digest_type;
};

struct keymaster_ec_sign_params {
    enum keymaster_digest_algorithm digest_type;
};

struct keymaster_rsa_sign_params {
    enum keymaster_digest_algorithm digest_type;
    enum keymaster_rsa_padding padding_type;
};


#endif  // ANDROID_HARDWARE_KEYMASTER_COMMON_H
