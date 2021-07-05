#include <stdio.h>
#include <string.h>
#if !defined(WIN32)
#include <x86intrin.h>
#endif

#include <openssl/ssl.h>
#include <openssl/aes.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

int set_priv_key_DH(DH *dh, const char *s_priv_key,
                    int (*cb_ssl_errors)(const char *str, size_t len,
                                         void *u)) {

  int res;
  int out_res = 0;
  BIGNUM *dh_priv_key = NULL;

  dh_priv_key = BN_new();
  res = BN_hex2bn(&dh_priv_key, s_priv_key);
  if (res == 0) {
    out_res = 1;
    fprintf(stderr, "BN_hex2bn failed with errors: %d\n", res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    goto error0;
  }
  res = DH_set0_key(dh, NULL, dh_priv_key);
  if (res != 1) {
    out_res = 1;
    fprintf(stderr, "DH_set0_key failed with errors: %d\n", res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    goto error0;
  }

  return out_res;
error0:
  BN_free(dh_priv_key);
  return out_res;
}

void print_DH(const DH *dh) {
  const BIGNUM *dh_p = NULL, *dh_g = NULL;
  char *str_dh_p = NULL, *str_dh_g = NULL;
  DH_get0_pqg(dh, &dh_p, NULL, &dh_g);
  str_dh_p = BN_bn2hex(dh_p);
  dh_p = NULL;
  printf("dh p = 0x%s\n", str_dh_p);
  OPENSSL_free(str_dh_p);
  str_dh_p = NULL;

  str_dh_g = BN_bn2hex(dh_g);
  dh_g = NULL;
  printf("dh g = 0x%s\n", str_dh_g);
  OPENSSL_free(str_dh_g);
  str_dh_g = NULL;

  const BIGNUM *dh_pub_key = NULL, *dh_priv_key = NULL;
  char *str_dh_pub_key = NULL, *str_dh_priv_key = NULL;
  DH_get0_key(dh, &dh_pub_key, &dh_priv_key);
  if (dh_pub_key != NULL) {
    str_dh_pub_key = BN_bn2hex(dh_pub_key);
  }
  dh_pub_key = NULL;
  if (str_dh_pub_key == NULL) {
    printf("dh pub_key = <error>\n");
  } else {
    printf("dh pub_key = |0x%s|\n", str_dh_pub_key);
  }
  OPENSSL_free(str_dh_pub_key);
  str_dh_pub_key = NULL;

  if (dh_priv_key != NULL) {
    str_dh_priv_key = BN_bn2hex(dh_priv_key);
  }
  dh_priv_key = NULL;
  if (str_dh_priv_key == NULL) {
    printf("dh priv_key = <error>\n");
  } else {
    printf("dh priv_key = |0x%s|\n", str_dh_priv_key);
  }
  OPENSSL_free(str_dh_priv_key);
  str_dh_priv_key = NULL;
}

unsigned char *HMAC_with_time(const EVP_MD *evp_md, const void *key,
                              int key_len, const unsigned char *d, size_t n,
                              unsigned char *md, unsigned int *md_len,
                              uint64_t *t_delta) {

  int res;
  uint64_t t_start;
  unsigned int core_id_start = 0, core_id_end = 0;
  uint64_t t_end;

  HMAC_CTX *c = NULL;

  if ((c = HMAC_CTX_new()) == NULL)
    goto err;

  t_start = __rdtscp(&core_id_start);
  res = HMAC_Init_ex(c, key, key_len, evp_md, NULL);
  t_end = __rdtscp(&core_id_end);
  if (res != 1) {
    goto err;
  }
  if (!HMAC_Update(c, d, n))
    goto err;
  if (!HMAC_Final(c, md, md_len))
    goto err;
  HMAC_CTX_free(c);

  if (t_delta != NULL) {
    if (core_id_start == core_id_end) {
      *t_delta = t_end - t_start;
    } else {
      *t_delta = 0;
    }
  }
  return md;

err:
  HMAC_CTX_free(c);
  return NULL;
}

unsigned char *hexstr2buf(const char *str, size_t *len) {
  unsigned char *hexbuf, *q;
  unsigned char ch, cl;
  int chi, cli;
  const unsigned char *p;
  size_t s;

  s = strlen(str);
  if ((hexbuf = OPENSSL_malloc(s >> 1)) == NULL) {
    CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  for (p = (const unsigned char *)str, q = hexbuf; *p;) {
    ch = *p++;
    cl = *p++;
    if (!cl) {
      CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF, CRYPTO_R_ODD_NUMBER_OF_DIGITS);
      OPENSSL_free(hexbuf);
      return NULL;
    }
    cli = OPENSSL_hexchar2int(cl);
    chi = OPENSSL_hexchar2int(ch);
    if (cli < 0 || chi < 0) {
      OPENSSL_free(hexbuf);
      CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF, CRYPTO_R_ILLEGAL_HEX_DIGIT);
      return NULL;
    }
    *q++ = (unsigned char)((chi << 4) | cli);
  }

  if (len)
    *len = q - hexbuf;
  return hexbuf;
}

char *buf2hexstr(const unsigned char *buffer, size_t len) {
  static const char hexdig[] = "0123456789ABCDEF";
  char *tmp, *q;
  const unsigned char *p;
  size_t i;

  if (len == 0) {
    return OPENSSL_zalloc(1);
  }

  if ((tmp = OPENSSL_malloc(len * 2 + 1)) == NULL) {
    CRYPTOerr(CRYPTO_F_OPENSSL_BUF2HEXSTR, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  q = tmp;
  for (i = 0, p = buffer; i < len; i++, p++) {
    *q++ = hexdig[(*p >> 4) & 0xf];
    *q++ = hexdig[*p & 0xf];
  }
  q[0] = 0;
  return tmp;
}

int decrypt_raccoon(
    EVP_CIPHER_CTX *ctx_evp_decrypt, const unsigned char *master_key,
    const unsigned char *iv_key, const unsigned char *encrypt_data,
    size_t size_encrypt_data, unsigned char *data, size_t *p_size_data,
    int (*cb_ssl_errors)(const char *str, size_t len, void *u)) {

  int res;
  size_t size_data;
  int size_out;

  res = EVP_CIPHER_CTX_reset(ctx_evp_decrypt);
  if (res != 1) {
    fprintf(stderr, "EVP_CIPHER_CTX_reset(decrypt) failed with errors: %d\n",
            res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 1;
  }

  res = EVP_DecryptInit_ex(ctx_evp_decrypt, EVP_aes_256_cbc(), NULL, master_key,
                           iv_key);
  if (res != 1) {
    fprintf(stderr, "EVP_DecryptInit_ex failed with errors: %d\n", res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 1;
    ;
  }
  EVP_CIPHER_CTX_set_padding(ctx_evp_decrypt, 0);
  if (*p_size_data < size_encrypt_data + AES_BLOCK_SIZE) {
    fprintf(stderr, "data is too large to decrypt\n");
    return 1;
  }

  size_data = 0;
  size_out = 0;
  res = EVP_DecryptUpdate(ctx_evp_decrypt, data, &size_out, encrypt_data,
                          (int)size_encrypt_data);
  if (res != 1) {
    fprintf(stderr, "EVP_DecryptUpdate failed with errors: %d\n", res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 1;
  }
  size_data += (size_t)size_out;

  if (*p_size_data < AES_BLOCK_SIZE + size_data) {
    fprintf(stderr, "data is too large to decrypt\n");
    return 1;
  }

  size_out = 0;
  res = EVP_DecryptFinal_ex(ctx_evp_decrypt, data + size_data, &size_out);
  if (res != 1) {
    fprintf(stderr, "EVP_DecryptFinal_ex failed with errors: %d\n", res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 1;
  }
  size_data += (size_t)size_out;

  *p_size_data = size_data;
  return 0;
}

unsigned char ZERO_BYTES[AES_BLOCK_SIZE] = {0, 0, 0, 0, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 0};

int encrypt_raccoon(
    EVP_CIPHER_CTX *ctx_evp_encrypt, const unsigned char *master_key,
    const unsigned char *iv_key, const unsigned char *data, size_t size_data,
    unsigned char *encrypt_data, size_t *p_encrypt_size_data,
    int (*cb_ssl_errors)(const char *str, size_t len, void *u)) {

  int res;
  size_t size_encypt_data;
  size_t padding;
  int size_out;

  res = EVP_CIPHER_CTX_reset(ctx_evp_encrypt);
  if (res != 1) {
    fprintf(stderr, "EVP_CIPHER_CTX_reset(encrypt) failed with errors: %d\n",
            res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 1;
  }

  res = EVP_EncryptInit_ex(ctx_evp_encrypt, EVP_aes_256_cbc(), NULL, master_key,
                           iv_key);
  if (res != 1) {
    fprintf(stderr, "EVP_EncryptInit_ex2 failed with errors: %d\n", res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 1;
  }
  EVP_CIPHER_CTX_set_padding(ctx_evp_encrypt, 0);

  padding = size_data % AES_BLOCK_SIZE;
  if (padding != 0) {
    padding = AES_BLOCK_SIZE - padding;
  }

  size_encypt_data = 0;
  // encrypt data
  if (*p_encrypt_size_data < size_data + padding + AES_BLOCK_SIZE) {
    fprintf(stderr, "data is too large to encrypt\n");
    return 1;
  }
  size_out = 0;
  res = EVP_EncryptUpdate(ctx_evp_encrypt, encrypt_data, &size_out, data,
                          (int)size_data);
  if (res != 1) {
    fprintf(stderr, "EVP_EncryptUpdate failed with errors: %d\n", res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 1;
  }
  size_encypt_data += (size_t)size_out;

  // encrypt padding
  if (*p_encrypt_size_data < AES_BLOCK_SIZE + padding + size_encypt_data) {
    fprintf(stderr, "data is too large to encrypt\n");
    return 1;
  }
  size_out = 0;
  res = EVP_EncryptUpdate(ctx_evp_encrypt, encrypt_data + size_encypt_data,
                          &size_out, ZERO_BYTES, (int)padding);
  if (res != 1) {
    fprintf(stderr, "EVP_EncryptUpdate failed with errors: %d\n", res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 1;
  }
  size_encypt_data += (size_t)size_out;

  // encrypt final
  if (*p_encrypt_size_data < AES_BLOCK_SIZE + size_encypt_data) {
    fprintf(stderr, "data is too large to encrypt\n");
    return 1;
  }
  size_out = 0;
  res = EVP_EncryptFinal_ex(ctx_evp_encrypt, encrypt_data + size_encypt_data,
                            &size_out);
  if (res != 1) {
    fprintf(stderr, "EVP_EncryptFinal_ex failed with errors: %d\n", res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 1;
  }
  size_encypt_data += (size_t)size_out;
  *p_encrypt_size_data = size_encypt_data;

  return 0;
}