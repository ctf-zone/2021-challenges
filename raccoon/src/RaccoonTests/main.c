#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <memory.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

#include "ssl_utils.h"
#include "cross.h"
#include "test_utils.h"
#include "raccoon.h"

static int cb_ssl_errors(const char *str, size_t len, void *bp) {

  if (len > INT16_MAX) {
    return -1;
  }
  fprintf(stderr, "\t%.*s\n", (int)len, str);
  return 1;
}

int test_msg_random() {
  {
    int res;
    unsigned char in_random[128] = "0123456789";
    unsigned char out_random[128];
    char buf[1024];
    size_t size_buf = 0;

    size_buf = msg_random(in_random, sizeof(in_random), buf, sizeof(buf), NULL);
    REGRESS_3(size_buf > 0, "msg_random: %" PRIuPTR, size_buf);

    res = parse_msg_random(buf, size_buf, out_random, sizeof(out_random), NULL);
    REGRESS_3(res == 0, "parse_msg_random: %d", res);

    res = memcmp(in_random, out_random, sizeof(out_random));
    if (res != 0) {
      char *hex_in_random = OPENSSL_buf2hexstr(in_random, sizeof(in_random));
      char *hex_out_random = OPENSSL_buf2hexstr(out_random, sizeof(out_random));
      printf("in_random!=out_random %s!=%s\n", hex_in_random, hex_out_random);
      OPENSSL_free(hex_in_random);
      OPENSSL_free(hex_out_random);
      REGRESS_ERROR();
    }
  }

  {
    unsigned char in_random[] = "0123456789";
    char buf[256];
    char ref_buf[] = "random 30313233343536373839\n";
    size_t size_buf = 0;

    size_buf =
        msg_random(in_random, sizeof(in_random) - 1, buf, sizeof(buf), NULL);
    REGRESS_3(size_buf > 0, "msg_random: %" PRIuPTR, size_buf);
    REGRESS_3(strcmp(ref_buf, buf) == 0, "%s!=%s\n", ref_buf, buf);
    REGRESS_3(size_buf == sizeof(ref_buf) - 1, "%" PRIuPTR "!=%" PRIuPTR "\n",
              size_buf, sizeof(ref_buf) - 1);
  }

  {
    int res;
    unsigned char out_random[128];
    unsigned char ref_random[128];
    char buf[] = "random a3f1b430\n";

    memset(ref_random, 0, sizeof(ref_random));
    memcpy_s(ref_random, sizeof(ref_random),
             "\xa3\xf1\xb4"
             "0",
             sizeof("\xa3\xf1\xb4"
                    "0") -
                 1);

    res = parse_msg_random(buf, sizeof(buf) - 1, out_random, sizeof(out_random),
                           NULL);
    REGRESS_3(res == 0, "parse_msg_random: %d", res);

    res = memcmp(ref_random, out_random, sizeof(out_random));
    if (res != 0) {
      char *hex_ref_random = OPENSSL_buf2hexstr(ref_random, sizeof(ref_random));
      char *hex_out_random = OPENSSL_buf2hexstr(out_random, sizeof(out_random));
      printf("hex_ref_random!=out_random %s!=%s\n", hex_ref_random,
             hex_out_random);
      OPENSSL_free(hex_ref_random);
      OPENSSL_free(hex_out_random);
      REGRESS_ERROR();
    };
  }

  return 0;
}

int test_msg_pub() {
  {
    int res;
    BIGNUM *pub_in = NULL;
    BIGNUM *pub_out = NULL;
    char buf[256];
    size_t size_buf = 0;

    pub_in = BN_new();
    REGRESS_2(pub_in != NULL, "BN_new");
    pub_out = BN_new();
    REGRESS_2(pub_out != NULL, "BN_new");

    res = BN_dec2bn(&pub_in, "173");
    REGRESS_3(res > 0, "BN_dec2bn: %d", res);

    size_buf = msg_pub(pub_in, buf, sizeof(buf), NULL);
    REGRESS_3(size_buf > 0, "msg_pub: %" PRIuPTR, size_buf);

    res = parse_msg_pub(buf, size_buf, pub_out, NULL);
    REGRESS_3(res == 0, "parse_msg_pub: %d", res);

    REGRESS_3(res == 0, "parse_msg_pub: %d", res);

    res = BN_cmp(pub_in, pub_out);
    if (res != 0) {
      char *hex_in_pub = BN_bn2hex(pub_in);
      char *hex_out_pub = BN_bn2hex(pub_out);
      printf("hex_in_pub!=hex_out_pub %s!=%s\n", hex_in_pub, hex_out_pub);
      OPENSSL_free(hex_in_pub);
      OPENSSL_free(hex_out_pub);
      REGRESS_ERROR();
    }

    BN_free(pub_in);
    BN_free(pub_out);
  }

  {
    int res;
    BIGNUM *pub_in = NULL;
    char buf[256];
    char ref_buf[] = "pub 30313233343536373839\n";
    size_t size_buf = 0;

    pub_in = BN_new();
    REGRESS_2(pub_in != NULL, "BN_new");
    res = BN_hex2bn(&pub_in, "30313233343536373839");
    REGRESS_3(res > 0, "BN_hex2bn: %d", res);

    size_buf = msg_pub(pub_in, buf, sizeof(buf), NULL);
    REGRESS_3(size_buf > 0, "msg_pub: %" PRIuPTR, size_buf);
    REGRESS_3(size_buf == sizeof(ref_buf) - 1, "%" PRIuPTR "!=%" PRIuPTR "\n",
              size_buf, sizeof(ref_buf) - 1);
    REGRESS_3(strcmp(ref_buf, buf) == 0, "%s!=%s\n", ref_buf, buf);

    BN_free(pub_in);
  }

  {
    int res;
    BIGNUM *pub_ref = NULL;
    BIGNUM *pub_out = NULL;
    char buf[] = "pub a3f1b430\n";

    pub_out = BN_new();
    REGRESS_2(pub_out != NULL, "BN_new");
    pub_ref = BN_new();
    REGRESS_2(pub_ref != NULL, "BN_new");
    res = BN_hex2bn(&pub_ref, "a3f1b430");
    REGRESS_3(res > 0, "BN_hex2bn: %d", res);

    res = parse_msg_pub(buf, sizeof(buf) - 1, pub_out, NULL);
    REGRESS_3(res == 0, "parse_msg_pub: %d", res);

    res = BN_cmp(pub_ref, pub_out);
    if (res != 0) {
      char *hex_ref_pub = BN_bn2hex(pub_ref);
      char *hex_out_pub = BN_bn2hex(pub_out);
      printf("hex_ref_pub!=hex_out_pub %s!=%s\n", hex_ref_pub, hex_out_pub);
      OPENSSL_free(hex_ref_pub);
      OPENSSL_free(hex_out_pub);
      REGRESS_ERROR();
    }

    BN_free(pub_out);
    BN_free(pub_ref);
  }

  return 0;
}

int test_msg_params() {
  {
    int res;
    BIGNUM *p_in = NULL, *g_in = NULL, *pub_in = NULL;
    BIGNUM *p_out = NULL, *g_out = NULL, *pub_out = NULL;
    char buf[256];
    size_t size_buf = 0;

    p_in = BN_new();
    REGRESS_2(p_in != NULL, "BN_new");
    g_in = BN_new();
    REGRESS_2(g_in != NULL, "BN_new");
    pub_in = BN_new();
    REGRESS_2(pub_in != NULL, "BN_new");
    p_out = BN_new();
    REGRESS_2(p_out != NULL, "BN_new");
    g_out = BN_new();
    REGRESS_2(g_out != NULL, "BN_new");
    pub_out = BN_new();
    REGRESS_2(pub_out != NULL, "BN_new");

    res = BN_dec2bn(&p_in, "17");
    REGRESS_3(res > 0, "BN_dec2bn: %d", res);
    res = BN_dec2bn(&g_in, "29");
    REGRESS_3(res > 0, "BN_dec2bn: %d", res);
    res = BN_dec2bn(&pub_in, "173");
    REGRESS_3(res > 0, "BN_dec2bn: %d", res);

    size_buf = msg_params(p_in, g_in, pub_in, buf, sizeof(buf), NULL);
    REGRESS_3(size_buf > 0, "msg_params: %" PRIuPTR, size_buf);

    res = parse_msg_params(buf, size_buf, p_out, g_out, pub_out, NULL);
    REGRESS_3(res == 0, "parse_msg_params: %d", res);

    res = BN_cmp(p_in, p_out);
    if (res != 0) {
      char *hex_in_p = BN_bn2hex(p_in);
      char *hex_out_p = BN_bn2hex(p_out);
      printf("hex_in_p!=hex_out_p %s!=%s\n", hex_in_p, hex_out_p);
      OPENSSL_free(hex_in_p);
      OPENSSL_free(hex_out_p);
      REGRESS_ERROR();
    }

    res = BN_cmp(g_in, g_out);
    if (res != 0) {
      char *hex_in_g = BN_bn2hex(g_in);
      char *hex_out_g = BN_bn2hex(g_out);
      printf("hex_in_g!=hex_out_pub %s!=%s\n", hex_in_g, hex_out_g);
      OPENSSL_free(hex_in_g);
      OPENSSL_free(hex_out_g);
      REGRESS_ERROR();
    }

    res = BN_cmp(pub_in, pub_out);
    if (res != 0) {
      char *hex_in_pub = BN_bn2hex(pub_in);
      char *hex_out_pub = BN_bn2hex(pub_out);
      printf("pub_in!=hex_out_pub %s!=%s\n", hex_in_pub, hex_out_pub);
      OPENSSL_free(hex_in_pub);
      OPENSSL_free(hex_out_pub);
      REGRESS_ERROR();
    }

    BN_free(p_in);
    BN_free(g_in);
    BN_free(pub_in);
    BN_free(p_out);
    BN_free(g_out);
    BN_free(pub_out);
  }

  {
    int res;
    BIGNUM *p_in = NULL, *g_in = NULL, *pub_in = NULL;
    BIGNUM *p_out = NULL, *g_out = NULL, *pub_out = NULL;
    char buf[256];
    char ref_buf[] = "p 33 g 57 pub AF12\n";
    size_t size_buf = 0;

    p_in = BN_new();
    REGRESS_2(p_in != NULL, "BN_new");
    res = BN_hex2bn(&p_in, "33");
    REGRESS_3(res > 0, "BN_hex2bn: %d", res);
    g_in = BN_new();
    REGRESS_2(g_in != NULL, "BN_new");
    res = BN_hex2bn(&g_in, "57");
    REGRESS_3(res > 0, "BN_hex2bn: %d", res);
    pub_in = BN_new();
    REGRESS_2(pub_in != NULL, "BN_new");
    res = BN_hex2bn(&pub_in, "af12");
    REGRESS_3(res > 0, "BN_hex2bn: %d", res);
    p_out = BN_new();
    REGRESS_2(p_out != NULL, "BN_new");
    g_out = BN_new();
    REGRESS_2(g_out != NULL, "BN_new");
    pub_out = BN_new();
    REGRESS_2(pub_out != NULL, "BN_new");

    size_buf = msg_params(p_in, g_in, pub_in, buf, sizeof(buf), NULL);
    REGRESS_3(size_buf > 0, "msg_params: %" PRIuPTR, size_buf);
    REGRESS_3(size_buf == sizeof(ref_buf) - 1, "%" PRIuPTR "!=%" PRIuPTR "\n",
              size_buf, sizeof(ref_buf) - 1);
    REGRESS_3(strcmp(ref_buf, buf) == 0, "%s!=%s\n", ref_buf, buf);

    BN_free(p_in);
    BN_free(g_in);
    BN_free(pub_in);
    BN_free(p_out);
    BN_free(g_out);
    BN_free(pub_out);
  }

  {
    int res;
    BIGNUM *p_ref = NULL, *g_ref = NULL, *pub_ref = NULL;
    BIGNUM *p_out = NULL, *g_out = NULL, *pub_out = NULL;
    char buf[] = "p 23 g 67 pub 12AF\n";

    p_ref = BN_new();
    REGRESS_2(p_ref != NULL, "BN_new");
    res = BN_hex2bn(&p_ref, "23");
    REGRESS_3(res > 0, "BN_hex2bn: %d", res);
    g_ref = BN_new();
    REGRESS_2(g_ref != NULL, "BN_new");
    res = BN_hex2bn(&g_ref, "67");
    REGRESS_3(res > 0, "BN_hex2bn: %d", res);
    pub_ref = BN_new();
    REGRESS_2(pub_ref != NULL, "BN_new");
    res = BN_hex2bn(&pub_ref, "12af");
    REGRESS_3(res > 0, "BN_hex2bn: %d", res);

    p_out = BN_new();
    REGRESS_2(p_out != NULL, "BN_new");
    g_out = BN_new();
    REGRESS_2(g_out != NULL, "BN_new");
    pub_out = BN_new();
    REGRESS_2(pub_out != NULL, "BN_new");

    res = parse_msg_params(buf, sizeof(buf) - 1, p_out, g_out, pub_out, NULL);
    REGRESS_3(res == 0, "parse_msg_pub: %d", res);

    res = BN_cmp(p_ref, p_out);
    if (res != 0) {
      char *hex_ref_p = BN_bn2hex(p_ref);
      char *hex_out_p = BN_bn2hex(p_out);
      printf("hex_ref_p!=hex_out_p %s!=%s\n", hex_ref_p, hex_out_p);
      OPENSSL_free(hex_ref_p);
      OPENSSL_free(hex_out_p);
      REGRESS_ERROR();
    }

    res = BN_cmp(g_ref, g_out);
    if (res != 0) {
      char *hex_ref_g = BN_bn2hex(g_ref);
      char *hex_out_g = BN_bn2hex(g_out);
      printf("hex_ref_g!=hex_out_g %s!=%s\n", hex_ref_g, hex_out_g);
      OPENSSL_free(hex_ref_g);
      OPENSSL_free(hex_out_g);
      REGRESS_ERROR();
    }

    res = BN_cmp(pub_ref, pub_out);
    if (res != 0) {
      char *hex_ref_pub = BN_bn2hex(pub_ref);
      char *hex_out_pub = BN_bn2hex(pub_out);
      printf("hex_ref_pub!=hex_out_pub %s!=%s\n", hex_ref_pub, hex_out_pub);
      OPENSSL_free(hex_ref_pub);
      OPENSSL_free(hex_out_pub);
      REGRESS_ERROR();
    }

    BN_free(p_ref);
    BN_free(g_ref);
    BN_free(pub_ref);
    BN_free(p_out);
    BN_free(g_out);
    BN_free(pub_out);
  }

  return 0;
}

int test_msg_time() {
  {
    int res;
    uint64_t time_in;
    uint64_t time_out;
    char buf[256];
    size_t size_buf = 0;

    time_in = 13;
    size_buf = msg_time(time_in, buf, sizeof(buf));
    REGRESS_3(size_buf > 0, "msg_time: %" PRIuPTR, size_buf);

    res = parse_msg_time(buf, size_buf, &time_out);
    REGRESS_3(res == 0, "parse_msg_time: %d", res);

    if (time_in != time_out) {
      printf("time_in!=time_out %" PRIu64 "!=%" PRIu64 "\n", time_in, time_out);
      REGRESS_ERROR();
    }
  }

  {
    uint64_t time_in = 29;
    char buf[256];
    char ref_buf[] = "time 1D\n";
    size_t size_buf = 0;

    size_buf = msg_time(time_in, buf, sizeof(buf));
    REGRESS_3(size_buf > 0, "msg_time: %" PRIuPTR, size_buf);
    REGRESS_3(size_buf == sizeof(ref_buf) - 1, "%" PRIuPTR "!=%" PRIuPTR "\n",
              size_buf, sizeof(ref_buf) - 1);
    REGRESS_3(strcmp(ref_buf, buf) == 0, "%s!=%s\n", ref_buf, buf);
  }

  {
    int res;
    uint64_t time_ref = 163;
    uint64_t time_out = 0;
    char buf[] = "time a3\n";

    res = parse_msg_time(buf, sizeof(buf) - 1, &time_out);
    REGRESS_3(res == 0, "parse_msg_time: %d", res);

    if (time_ref != time_out) {
      printf("time_ref!=time_out %" PRIu64 "!=%" PRIu64 "\n", time_ref,
             time_out);
      REGRESS_ERROR();
    }
  }

  return 0;
}

int test_msg_encrypt() {
  {
    int res;
    unsigned char in_data[] = "0123456789";
    unsigned char in_iv_key[AES_BLOCK_SIZE] = "0987654321";
    unsigned char out_data[128];
    size_t size_out_data;
    unsigned char out_iv_key[AES_BLOCK_SIZE];
    char buf[256];
    size_t size_buf = 0;

    size_buf = msg_encrypt(in_data, sizeof(in_data) - 1, in_iv_key, buf,
                           sizeof(buf), NULL);
    REGRESS_3(size_buf > 0, "msg_encrypt: %" PRIuPTR, size_buf);

    size_out_data = sizeof(out_data);
    res = parse_msg_encrypt(buf, size_buf, out_data, &size_out_data, out_iv_key,
                            NULL);
    REGRESS_3(res == 0, "parse_msg_encrypt: %d", res);
    REGRESS_3(size_out_data == sizeof(in_data) - 1,
              "parse_msg_encrypt %" PRIuPTR "!= %" PRIuPTR, size_out_data,
              sizeof(in_data) - 1);

    res = memcmp(in_data, out_data, sizeof(in_data) - 1);
    if (res != 0) {
      char *hex_in_data = OPENSSL_buf2hexstr(in_data, sizeof(in_data));
      char *hex_out_data = OPENSSL_buf2hexstr(out_data, sizeof(out_data));
      printf("hex_in_data!=hex_out_data %s!=%s\n", hex_in_data, hex_out_data);
      OPENSSL_free(hex_in_data);
      OPENSSL_free(hex_out_data);
      REGRESS_ERROR();
    }

    res = memcmp(in_iv_key, out_iv_key, AES_BLOCK_SIZE);
    if (res != 0) {
      char *hex_in_iv_key = OPENSSL_buf2hexstr(in_iv_key, sizeof(in_iv_key));
      char *hex_out_iv_key = OPENSSL_buf2hexstr(out_iv_key, sizeof(out_iv_key));
      printf("hex_in_iv_key!=hex_out_iv_key %s!=%s\n", hex_in_iv_key,
             hex_out_iv_key);
      OPENSSL_free(hex_in_iv_key);
      OPENSSL_free(hex_out_iv_key);
      REGRESS_ERROR();
    }
  }

  {
    unsigned char in_iv_key[AES_BLOCK_SIZE] = "0987654321234567";
    unsigned char in_data[] = "0123456789";
    char ref_buf[] =
        "iv 30393837363534333231323334353637 data 30313233343536373839\n";
    char buf[256];
    size_t size_buf = 0;

    size_buf = msg_encrypt(in_data, sizeof(in_data) - 1, in_iv_key, buf,
                           sizeof(buf), NULL);
    REGRESS_3(size_buf > 0, "msg_encrypt: %" PRIuPTR, size_buf);
    REGRESS_3(strcmp(ref_buf, buf) == 0, "%s!=%s\n", ref_buf, buf);
    REGRESS_3(size_buf == sizeof(ref_buf) - 1, "%" PRIuPTR "!=%" PRIuPTR "\n",
              size_buf, sizeof(ref_buf) - 1);
  }

  {
    int res;
    unsigned char out_iv_key[AES_BLOCK_SIZE];
    unsigned char ref_iv_key[AES_BLOCK_SIZE] =
        "\xbc\xd7\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    unsigned char out_data[128];
    unsigned char ref_data[] = "\xa3\xf1\xb4\x30";
    size_t size_out_data;
    char buf[] = "iv BCD7 data A3F1B430\n";

    size_out_data = sizeof(out_data);
    res = parse_msg_encrypt(buf, sizeof(buf) - 1, out_data, &size_out_data,
                            out_iv_key, NULL);
    REGRESS_3(res == 0, "parse_msg_encrypt: %d", res);
    REGRESS_3(size_out_data == sizeof(ref_data) - 1,
              "parse_msg_encrypt %" PRIuPTR "!= %" PRIuPTR, size_out_data,
              sizeof(ref_data) - 1);

    res = memcmp(out_data, ref_data, sizeof(ref_data) - 1);
    if (res != 0) {
      char *hex_ref_data = OPENSSL_buf2hexstr(ref_data, sizeof(ref_data));
      char *hex_out_data = OPENSSL_buf2hexstr(out_data, sizeof(out_data));
      printf("hex_ref_data!=hex_out_data %s!=%s\n", hex_ref_data, hex_out_data);
      OPENSSL_free(hex_ref_data);
      OPENSSL_free(hex_out_data);
      REGRESS_ERROR();
    }

    res = memcmp(out_iv_key, ref_iv_key, AES_BLOCK_SIZE);
    if (res != 0) {
      char *hex_ref_iv_key = OPENSSL_buf2hexstr(ref_iv_key, sizeof(ref_iv_key));
      char *hex_out_iv_key = OPENSSL_buf2hexstr(out_iv_key, sizeof(out_iv_key));
      printf("hex_ref_iv_key!=hex_out_iv_key %s!=%s\n", hex_ref_iv_key,
             hex_out_iv_key);
      OPENSSL_free(hex_ref_iv_key);
      OPENSSL_free(hex_out_iv_key);
      REGRESS_ERROR();
    }
  }

  return 0;
}

int test_crypt() {
  int res;
  unsigned char ref_data[] = "raccoon";
  unsigned char data[128];
  unsigned char encrypt_data[128];
  size_t size_encrypt_data, size_data;
  unsigned char master_key[SHA256_DIGEST_LENGTH], iv_key[AES_BLOCK_SIZE];
  EVP_CIPHER_CTX *ctx_evp_encrypt = NULL, *ctx_evp_decrypt = NULL;

  res = RAND_bytes(master_key, SHA256_DIGEST_LENGTH);
  REGRESS_3(res == 1, "RAND_bytes: %d", res);
  res = RAND_bytes(iv_key, AES_BLOCK_SIZE);
  REGRESS_3(res == 1, "RAND_bytes: %d", res);

  ctx_evp_encrypt = EVP_CIPHER_CTX_new();
  REGRESS_2(ctx_evp_encrypt != NULL, "EVP_CIPHER_CTX_new");
  ctx_evp_decrypt = EVP_CIPHER_CTX_new();
  REGRESS_2(ctx_evp_decrypt != NULL, "EVP_CIPHER_CTX_new");

  size_encrypt_data = sizeof(encrypt_data);
  res = encrypt_raccoon(ctx_evp_encrypt, master_key, iv_key, ref_data,
                        sizeof(ref_data) - 1, encrypt_data, &size_encrypt_data,
                        cb_ssl_errors);
  REGRESS_3(res == 0, "encrypt: %d", res);

  size_data = sizeof(data);
  res = decrypt_raccoon(ctx_evp_decrypt, master_key, iv_key, encrypt_data,
                        size_encrypt_data, data, &size_data, cb_ssl_errors);
  REGRESS_3(res == 0, "decrypt: %d", res);
  REGRESS_3(strlen((char *)ref_data) == sizeof(ref_data) - 1,
            "decrypt: %" PRIuPTR "[%" PRIuPTR "]!= %" PRIuPTR,
            strlen((char *)ref_data), size_data, sizeof(ref_data) - 1);

  res = memcmp(data, ref_data, strlen((char *)ref_data));
  if (res != 0) {
    char *hex_ref_data =
        OPENSSL_buf2hexstr(ref_data, (long)(sizeof(ref_data) - 1));
    char *hex_data = OPENSSL_buf2hexstr(data, (long)size_data);
    printf("hex_ref_data!=hex_data %s!=%s\n", hex_ref_data, hex_data);
    OPENSSL_free(hex_ref_data);
    OPENSSL_free(hex_data);
    REGRESS_ERROR();
  }

  EVP_CIPHER_CTX_free(ctx_evp_decrypt);
  EVP_CIPHER_CTX_free(ctx_evp_encrypt);

  return 0;
}

int test_crypt_big() {
  int res;
  unsigned char ref_data[] = "_____________raccoon___________________";
  unsigned char data[128];
  unsigned char encrypt_data[128];
  size_t size_encrypt_data, size_data;
  unsigned char master_key[SHA256_DIGEST_LENGTH], iv_key[AES_BLOCK_SIZE];
  EVP_CIPHER_CTX *ctx_evp_encrypt = NULL, *ctx_evp_decrypt = NULL;

  res = RAND_bytes(master_key, SHA256_DIGEST_LENGTH);
  REGRESS_3(res == 1, "RAND_bytes: %d", res);
  res = RAND_bytes(iv_key, AES_BLOCK_SIZE);
  REGRESS_3(res == 1, "RAND_bytes: %d", res);

  ctx_evp_encrypt = EVP_CIPHER_CTX_new();
  REGRESS_2(ctx_evp_encrypt != NULL, "EVP_CIPHER_CTX_new");
  ctx_evp_decrypt = EVP_CIPHER_CTX_new();
  REGRESS_2(ctx_evp_decrypt != NULL, "EVP_CIPHER_CTX_new");

  size_encrypt_data = sizeof(encrypt_data);
  res = encrypt_raccoon(ctx_evp_encrypt, master_key, iv_key, ref_data,
                        sizeof(ref_data) - 1, encrypt_data, &size_encrypt_data,
                        cb_ssl_errors);
  REGRESS_3(res == 0, "encrypt: %d", res);

  size_data = sizeof(data);
  res = decrypt_raccoon(ctx_evp_decrypt, master_key, iv_key, encrypt_data,
                        size_encrypt_data, data, &size_data, cb_ssl_errors);
  REGRESS_3(res == 0, "decrypt: %d", res);
  REGRESS_3(strlen((char *)ref_data) == sizeof(ref_data) - 1,
            "decrypt: %" PRIuPTR "[%" PRIuPTR "]!= %" PRIuPTR,
            strlen((char *)ref_data), size_data, sizeof(ref_data) - 1);

  res = memcmp(data, ref_data, strlen((char *)ref_data));
  if (res != 0) {
    char *hex_ref_data =
        OPENSSL_buf2hexstr(ref_data, (long)(sizeof(ref_data) - 1));
    char *hex_data = OPENSSL_buf2hexstr(data, (long)size_data);
    printf("hex_ref_data!=hex_data %s!=%s\n", hex_ref_data, hex_data);
    OPENSSL_free(hex_ref_data);
    OPENSSL_free(hex_data);
    REGRESS_ERROR();
  }

  EVP_CIPHER_CTX_free(ctx_evp_decrypt);
  EVP_CIPHER_CTX_free(ctx_evp_encrypt);

  return 0;
}

int main() {
  printf("test_msg_random\n");
  REGRESS_2(test_msg_random() == 0, "test_msg_random");
  printf("test_msg_pub\n");
  REGRESS_2(test_msg_pub() == 0, "test_msg_pub");
  printf("test_msg_params\n");
  REGRESS_2(test_msg_params() == 0, "test_msg_params");
  printf("test_msg_encrypt\n");
  REGRESS_2(test_msg_encrypt() == 0, "test_msg_encrypt");
  printf("test_msg_time\n");
  REGRESS_2(test_msg_time() == 0, "test_msg_time");

  printf("test_crypt\n");
  REGRESS_2(test_crypt() == 0, "test_crypt");
  REGRESS_2(test_crypt_big() == 0, "test_crypt_big");

  return 0;
}