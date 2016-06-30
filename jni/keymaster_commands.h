#ifndef __KEYMASTER_COMMANDS_H__
#define __KEYMASTER_COMMANDS_H__

#include "QSEEComAPI.h"
#include "keymaster_common.h"
#include "keymaster_qcom.h"

/**
 * Indicates a successful keymaster command execution
 */
#define KEYMATER_SUCCESS  0

/**
 * Indicates a failed keymaster command execution
 */
#define KEYMASTER_FAILURE  -1

/**
 * Generates a keymaster key and ignores the result.
 * @param km_handle The handle used to communicate with the keymaster application.
 * @param key_blob (out) The generated key blob.
 * @param key_blob_length (out) The generated key blob's length.
 * @return Zero if successful, a negative error code otherwise.
 */
int generate_keymaster_key(struct qcom_keymaster_handle* km_handle,
						   uint8_t** key_blob, size_t* key_blob_length);

/**
 * Generates a keymaster keypair using the given parameters.
 * @param handle The handle used to communicate with the keymaster application.
 * @param key_type The type of key being generated.
 * @param key_params The parameters used for the key generation.
 * @param keyBlob (out) The generated key blob.
 * @param keyBlobLength (out) The generated key blob's length.
 * @return Zero if successful, a negative error code otherwise.
 */
int keymaster_generate_keypair(struct qcom_keymaster_handle* handle,
                               enum keymaster_keypair key_type, const void* key_params,
                               uint8_t** keyBlob, size_t* keyBlobLength);

#endif
