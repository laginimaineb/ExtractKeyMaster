#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "keymaster_commands.h"
#include "keymaster_common.h"
#include "keymaster_qcom.h"

int generate_keymaster_key(struct qcom_keymaster_handle* km_handle, uint8_t** key_blob, size_t* key_blob_length) {

    //Generating a keypair using the keymaster application, to cause the KEK 
    //and IV to be loaded into the application!
    struct keymaster_rsa_keygen_params rsa_params;
    rsa_params.modulus_size = 1024;
    rsa_params.public_exponent = 3;
    int res = keymaster_generate_keypair(km_handle, TYPE_RSA, &rsa_params, key_blob, key_blob_length);
    if (res < 0) {
        perror("[-] Failed to generate RSA keypair");
        return -EINVAL;
    }

	//Dumping the keypair blob
    printf("[+] Generated encrypted keypair blob!\n");
//    for (uint32_t i=0; i<*key_blob_length; i++)
//        printf("%02X", (*key_blob)[i]);
//    printf("\n");

    return 0;
}

int keymaster_generate_keypair(struct qcom_keymaster_handle* handle,
							   enum keymaster_keypair key_type, const void* key_params,
							   uint8_t** keyBlob, size_t* keyBlobLength) {

	//Initializing the request and response buffers
	uint32_t cmd_req_size = QSEECOM_ALIGN(sizeof(struct keymaster_gen_keypair_cmd));
	uint32_t cmd_resp_size = QSEECOM_ALIGN(sizeof(struct keymaster_gen_keypair_resp));
	uint32_t* cmd_req = malloc(cmd_req_size);
	uint32_t* cmd_resp = malloc(cmd_resp_size);
	memset(cmd_req, 0, cmd_req_size);
	memset(cmd_resp, 0, cmd_resp_size);
	struct keymaster_rsa_keygen_params* rsa_params = (struct keymaster_rsa_keygen_params*) key_params;

	//Filling in the request data
	((struct keymaster_gen_keypair_cmd*)cmd_req)->cmd_id = KEYMASTER_GENERATE_KEYPAIR;
	((struct keymaster_gen_keypair_cmd*)cmd_req)->key_type = key_type;
	((struct keymaster_gen_keypair_cmd*)cmd_req)->rsa_params.modulus_size = rsa_params->modulus_size;
	((struct keymaster_gen_keypair_cmd*)cmd_req)->rsa_params.public_exponent = rsa_params->public_exponent;

	//Filling in the response data
	((struct keymaster_gen_keypair_resp*)cmd_resp)->status = KEYMASTER_FAILURE;
	((struct keymaster_gen_keypair_resp*)cmd_resp)->key_blob_len = sizeof(struct qcom_km_key_blob);
	
	//Sending the command
	int res = (*handle->QSEECom_set_bandwidth)(handle->qseecom, true);
    if (res < 0) {
        free(cmd_req);
        free(cmd_resp);
        perror("[-] Unable to enable clks");
        return -errno;
    }

    res = (*handle->QSEECom_send_cmd)(handle->qseecom,
                                      cmd_req,
                                      cmd_req_size,
                                      cmd_resp,
                                      cmd_resp_size);

    if ((*handle->QSEECom_set_bandwidth)(handle->qseecom, false)) {
        perror("[-] Import key command: (unable to disable clks)");
    }

	//Writing back the data to the user
	*keyBlobLength = ((struct keymaster_gen_keypair_resp*)cmd_resp)->key_blob_len;
	*keyBlob = malloc(*keyBlobLength);
	memcpy(*keyBlob, &(((struct keymaster_gen_keypair_resp*)cmd_resp)->key_blob), *keyBlobLength); 

	//Freeing the request and response buffers
    free(cmd_req);
    free(cmd_resp);
	
	return res;
}
