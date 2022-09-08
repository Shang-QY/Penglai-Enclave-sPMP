#ifndef _ATTEST_H
#define _ATTEST_H

#include "sm/enclave.h"

void attest_init();

void hash_enclave(struct enclave_t* enclave, void* hash, uintptr_t nonce);

void update_enclave_hash(char *output, void* hash, uintptr_t nonce_arg);

void sign_enclave(void* signature, unsigned char *message, int len);

int verify_enclave(void* signature, unsigned char *message, int len);

int verify_signature(void* signature_arg, unsigned char *message, int len, unsigned char *pubkey_arg);
#endif /* _ATTEST_H */
