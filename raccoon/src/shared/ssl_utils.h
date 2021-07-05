#ifndef SSL_UTILS_H
#define SSL_UTILS_H

#include <openssl/dh.h>

unsigned char *hexstr2buf(const char *str, size_t *len);
char *buf2hexstr(const unsigned char *buffer, size_t len);

int set_priv_key_DH(DH *dh, const char *s_priv_key,
                    int (*cb_ssl_errors)(const char *str, size_t len, void *u));

void print_DH(const DH *dh);

unsigned char *HMAC_with_time(const EVP_MD *evp_md, const void *key,
                              int key_len, const unsigned char *d, size_t n,
                              unsigned char *md, unsigned int *md_len,
                              uint64_t *t_delta);

int decrypt_raccoon(EVP_CIPHER_CTX *ctx_evp_decrypt,
                    const unsigned char *master_key,
                    const unsigned char *iv_key,
                    const unsigned char *encrypt_data, size_t size_encrypt_data,
                    unsigned char *data, size_t *p_size_data,
                    int (*cb_ssl_errors)(const char *str, size_t len, void *u));

int encrypt_raccoon(EVP_CIPHER_CTX *ctx_evp_encrypt,
                    const unsigned char *master_key,
                    const unsigned char *iv_key, const unsigned char *data,
                    size_t size_data, unsigned char *encrypt_data,
                    size_t *p_encrypt_size_data,
                    int (*cb_ssl_errors)(const char *str, size_t len, void *u));

#endif // SSL_UTILS_H