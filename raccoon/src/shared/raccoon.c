#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "net_utils.h"
#include "ssl_utils.h"
#include "cross.h"
#include "raccoon.h"

msg_type get_msg_type(const char *buf, size_t size_buf) {
  int res;
  res = strncmp(buf, "random ", min(sizeof("random ") - 1, size_buf));
  if (res == 0) {
    return mt_random;
  }
  res = strncmp(buf, "pub ", min(sizeof("pub ") - 1, size_buf));
  if (res == 0) {
    return mt_pub;
  }
  res = strncmp(buf, "p ", min(sizeof("p ") - 1, size_buf));
  if (res == 0) {
    return mt_params;
  }
  res = strncmp(buf, "iv ", min(sizeof("iv ") - 1, size_buf));
  if (res == 0) {
    return mt_data;
  }
  res = strncmp(buf, "time ", min(sizeof("time ") - 1, size_buf));
  if (res == 0) {
    return mt_time;
  }
  res = strncmp(buf, "close\n", min(sizeof("close\n") - 1, size_buf));
  if (res == 0) {
    return mt_close;
  }
  return mt_unknown;
}

size_t msg_random(const unsigned char *random, size_t size_random, char *buf,
                  size_t size_buf,
                  int (*cb_ssl_errors)(const char *str, size_t len, void *u)) {

  errno_t err;
  char *hex_out;

  buf[0] = 0;
  err = strcat_s(buf, size_buf, "random ");
  if (err != 0) {
    fprintf(stderr, "strcat_s failed with errors: %d\n", err);
    return 0;
  }

  hex_out = buf2hexstr(random, size_random);
  if (hex_out == NULL) {
    fprintf(stderr, "OPENSSL_buf2hexstr failed with errors\n");
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 0;
  }
  err = strcat_s(buf, size_buf, hex_out);
  OPENSSL_free(hex_out);
  hex_out = NULL;
  if (err != 0) {
    fprintf(stderr, "strcat_s(hex_random) failed with errors: %d\n", err);
    return 0;
  }

  err = strcat_s(buf, size_buf, "\n");
  if (err != 0) {
    fprintf(stderr, "strcat_s(endline) failed with errors: %d\n", err);
    return 0;
  }

  return strlen(buf);
}

size_t msg_pub(const BIGNUM *dh_pub, char *buf, size_t size_buf,
               int (*cb_ssl_errors)(const char *str, size_t len, void *u)) {

  errno_t err;
  size_t size_msg = 0;
  char *str_pub = NULL;

  buf[0] = 0;
  err = strcat_s(buf, size_buf, "pub ");
  if (err != 0) {
    fprintf(stderr, "strcat_s failed with errors: %d\n", err);
    return 0;
  }

  str_pub = BN_bn2hex(dh_pub);
  if (str_pub == NULL) {
    fprintf(stderr, "BN_bn2hex(dh_pub) failed with errors\n");
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 0;
  }
  err = strcat_s(buf, size_buf, str_pub);
  OPENSSL_free(str_pub);
  if (err != 0) {
    fprintf(stderr, "strcat_s failed with errors: %d\n", err);
    return 0;
  }

  err = strcat_s(buf, size_buf, "\n");
  if (err != 0) {
    fprintf(stderr, "strcat_s failed with errors: %d\n", err);
    return 0;
  }
  size_msg = strlen(buf);
  return size_msg;
}

size_t msg_params(const BIGNUM *dh_p, const BIGNUM *dh_g, const BIGNUM *dh_pub,
                  char *buf, size_t size_buf,
                  int (*cb_ssl_errors)(const char *str, size_t len, void *u)) {

  errno_t err;
  size_t size_msg = 0;
  char *str_param = NULL;

  buf[0] = 0;
  err = strcat_s(buf, size_buf, "p ");
  if (err != 0) {
    fprintf(stderr, "strcat_s failed with errors: %d\n", err);
    return 0;
  }
  str_param = BN_bn2hex(dh_p);
  if (str_param == NULL) {
    fprintf(stderr, "BN_bn2hex(dh_p) failed with errors\n");
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 0;
  }
  err = strcat_s(buf, size_buf, str_param);
  OPENSSL_free(str_param);
  str_param = NULL;
  if (err != 0) {
    fprintf(stderr, "strcat_s failed with errors: %d\n", err);
    return 0;
  }

  err = strcat_s(buf, size_buf, " g ");
  if (err != 0) {
    fprintf(stderr, "strcat_s failed with errors: %d\n", err);
    return 0;
  }
  str_param = BN_bn2hex(dh_g);
  if (str_param == NULL) {
    fprintf(stderr, "BN_bn2hex(dh_g) failed with errors\n");
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 0;
  }
  err = strcat_s(buf, size_buf, str_param);
  OPENSSL_free(str_param);
  str_param = NULL;
  if (err != 0) {
    fprintf(stderr, "strcat_s failed with errors: %d\n", err);
    return 0;
  }

  err = strcat_s(buf, size_buf, " pub ");
  if (err != 0) {
    fprintf(stderr, "strcat_s failed with errors: %d\n", err);
    return 0;
  }
  str_param = BN_bn2hex(dh_pub);
  if (str_param == NULL) {
    fprintf(stderr, "BN_bn2hex(dh_g) failed with errors\n");
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 0;
  }
  err = strcat_s(buf, size_buf, str_param);
  OPENSSL_free(str_param);
  str_param = NULL;
  if (err != 0) {
    fprintf(stderr, "strcat_s failed with errors: %d\n", err);
    return 0;
  }

  err = strcat_s(buf, size_buf, "\n");
  if (err != 0) {
    fprintf(stderr, "strcat_s failed with errors: %d\n", err);
    return 0;
  }
  size_msg = strlen(buf);
  return size_msg;
}

size_t msg_encrypt(const void *encrypt_data, size_t len_encrypt_data,
                   const unsigned char *iv_key, char *buf, size_t size_buf,
                   int (*cb_ssl_errors)(const char *str, size_t len, void *u)) {

  errno_t err;
  char *out_hex = NULL;

  buf[0] = 0;
  err = strcat_s(buf, size_buf, "iv ");
  if (err != 0) {
    fprintf(stderr, "strcat_s failed with errors: %d\n", err);
    return 0;
  }

  out_hex = buf2hexstr(iv_key, AES_BLOCK_SIZE);
  if (out_hex == NULL) {
    fprintf(stderr, "OPENSSL_buf2hexstr(iv) failed with errors\n");
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 0;
  }

  err = strcat_s(buf, size_buf, out_hex);
  OPENSSL_free(out_hex);
  out_hex = NULL;
  if (err != 0) {
    fprintf(stderr, "strcat_s(iv_hex) failed with errors: %d\n", err);
    return 0;
  }

  err = strcat_s(buf, size_buf, " data ");
  if (err != 0) {
    fprintf(stderr, "strcat_s(data) failed with errors: %d\n", err);
    return 0;
  }

  out_hex = buf2hexstr(encrypt_data, len_encrypt_data);
  if (out_hex == NULL) {
    fprintf(stderr, "OPENSSL_buf2hexstr(data) failed with errors\n");
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 0;
  }

  err = strcat_s(buf, size_buf, out_hex);
  OPENSSL_free(out_hex);
  out_hex = NULL;
  if (err != 0) {
    fprintf(stderr, "strcat_s(data_hex) failed with errors: %d\n", err);
    return 0;
  }

  err = strcat_s(buf, size_buf, "\n");
  if (err != 0) {
    fprintf(stderr, "strcat_s failed with errors: %d\n", err);
    return 0;
  }

  return strlen(buf);
}

size_t msg_close(char *buf, size_t size_buf) {
  errno_t err;

  buf[0] = 0;
  err = strcat_s(buf, size_buf, "close\n");
  if (err != 0) {
    fprintf(stderr, "strcat_s failed with errors: %d\n", err);
    return 0;
  }

  return strlen(buf);
}

size_t msg_time(uint64_t time, char *buf, size_t size_buf) {
  int res;

  buf[0] = 0;
  res = sprintf_s(buf, size_buf, "time %" PRIX64 "\n", time);
  if (res == -1) {
    fprintf(stderr, "_snprintf_s failed with errors\n");
    return 0;
  }

  return strlen(buf);
}

int parse_msg_random(char *buf, size_t size_buf, unsigned char *random,
                     size_t size_random,
                     int (*cb_ssl_errors)(const char *str, size_t len,
                                          void *u)) {

  errno_t err;
  int res;

  size_t out_size_random = 0;
  unsigned char *tmp_random;
  size_t offset = 0;
  size_t end_hex = 0;

  res = strncmp(buf, "random ", min(sizeof("random ") - 1, size_buf));
  if (res != 0) {
    fprintf(stderr, "Message not have random\n");
    return 1;
  }
  offset += sizeof("random ") - 1;
  for (end_hex = offset; end_hex < size_buf - 1; end_hex += 1) {
    if ((buf[end_hex] >= '0' && buf[end_hex] <= '9') ||
        (buf[end_hex] >= 'a' && buf[end_hex] <= 'f') ||
        (buf[end_hex] >= 'A' && buf[end_hex] <= 'F')) {

    } else {
      fprintf(stderr, "Message have not hex random\n");
      return 1;
    }
  }
  if (buf[end_hex] != '\n') {
    fprintf(stderr, "Message have invalid random\n");
    return 1;
  }
  buf[end_hex] = 0;
  out_size_random = 0;
  tmp_random = hexstr2buf(buf + offset, &out_size_random);
  if (tmp_random == NULL) {
    fprintf(stderr, "OPENSSL_hexstr2buf failed with errors\n");
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 1;
  }

  memset(random, 0, size_random);
  err = memcpy_s(random, size_random, tmp_random, (size_t)out_size_random);
  OPENSSL_free(tmp_random);
  tmp_random = NULL;
  if (err != 0) {
    fprintf(stderr, "memcpy_s failed with errors: %d\n", err);
    return 1;
  }

  return 0;
}

int parse_msg_params(char *buf, size_t size_buf, BIGNUM *dh_p, BIGNUM *dh_g,
                     BIGNUM *dh_pub,
                     int (*cb_ssl_errors)(const char *str, size_t len,
                                          void *u)) {

  int res;

  size_t offset = 0;
  size_t end_hex = 0;

  res = strncmp(buf + offset, "p ", min(sizeof("p ") - 1, size_buf - offset));
  if (res != 0) {
    fprintf(stderr, "Message not have p\n");
    return 1;
  }
  offset += sizeof("p ") - 1;
  for (end_hex = offset; end_hex < size_buf - 1 && buf[end_hex] != ' ';
       end_hex += 1) {
    if ((buf[end_hex] >= '0' && buf[end_hex] <= '9') ||
        (buf[end_hex] >= 'a' && buf[end_hex] <= 'f') ||
        (buf[end_hex] >= 'A' && buf[end_hex] <= 'F')) {

    } else {
      fprintf(stderr, "Message have not hex p\n");
      return 1;
    }
  }
  if (buf[end_hex] != ' ') {
    fprintf(stderr, "Message have invalid p\n");
    return 1;
  }
  buf[end_hex] = 0;
  res = BN_hex2bn(&dh_p, buf + offset);
  if ((size_t)res != end_hex - offset) {
    fprintf(stderr, "BN_hex2bn(dh_p) failed with errors: %d\n", res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 1;
  }
  offset = end_hex + 1;

  res = strncmp(buf + offset, "g ", min(sizeof("g ") - 1, size_buf - offset));
  if (res != 0) {
    fprintf(stderr, "Message not have p\n");
    return 1;
  }
  offset += sizeof("g ") - 1;
  for (end_hex = offset; end_hex < size_buf - 1 && buf[end_hex] != ' ';
       end_hex += 1) {
    if ((buf[end_hex] >= '0' && buf[end_hex] <= '9') ||
        (buf[end_hex] >= 'a' && buf[end_hex] <= 'f') ||
        (buf[end_hex] >= 'A' && buf[end_hex] <= 'F')) {

    } else {
      fprintf(stderr, "Message have not hex g\n");
      return 1;
    }
  }
  if (buf[end_hex] != ' ') {
    fprintf(stderr, "Message have invalid g\n");
    return 1;
  }
  buf[end_hex] = 0;
  res = BN_hex2bn(&dh_g, buf + offset);
  if ((size_t)res != end_hex - offset) {
    fprintf(stderr, "BN_hex2bn(dh_g) failed with errors: %d\n", res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 1;
  }
  offset = end_hex + 1;

  res =
      strncmp(buf + offset, "pub ", min(sizeof("pub ") - 1, size_buf - offset));
  if (res != 0) {
    fprintf(stderr, "Message not have pub\n");
    return 1;
  }
  offset += sizeof("pub ") - 1;
  for (end_hex = offset; end_hex < size_buf - 1; end_hex += 1) {
    if ((buf[end_hex] >= '0' && buf[end_hex] <= '9') ||
        (buf[end_hex] >= 'a' && buf[end_hex] <= 'f') ||
        (buf[end_hex] >= 'A' && buf[end_hex] <= 'F')) {

    } else {
      fprintf(stderr, "Message have not hex pub\n");
      return 1;
    }
  }
  if (buf[end_hex] != '\n') {
    fprintf(stderr, "Message have invalid pub\n");
    return 1;
  }
  buf[end_hex] = 0;
  res = BN_hex2bn(&dh_pub, buf + offset);
  if ((size_t)res != end_hex - offset) {
    fprintf(stderr, "BN_hex2bn(dh_pub) failed with errors: %d\n", res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 1;
  }

  return 0;
}

int parse_msg_pub(char *buf, size_t size_buf, BIGNUM *dh_pub,
                  int (*cb_ssl_errors)(const char *str, size_t len, void *u)) {

  int res;

  size_t offset = 0;
  size_t end_hex = 0;

  res =
      strncmp(buf + offset, "pub ", min(sizeof("pub ") - 1, size_buf - offset));
  if (res != 0) {
    fprintf(stderr, "Message not have pub\n");
    return 1;
  }
  offset += sizeof("pub ") - 1;
  for (end_hex = offset; end_hex < size_buf - 1; end_hex += 1) {
    if ((buf[end_hex] >= '0' && buf[end_hex] <= '9') ||
        (buf[end_hex] >= 'a' && buf[end_hex] <= 'f') ||
        (buf[end_hex] >= 'A' && buf[end_hex] <= 'F')) {

    } else {
      fprintf(stderr, "Message have not hex pub\n");
      return 1;
    }
  }
  if (buf[end_hex] != '\n') {
    fprintf(stderr, "Message have invalid pub\n");
    return 1;
  }
  buf[end_hex] = 0;
  res = BN_hex2bn(&dh_pub, buf + offset);
  if ((size_t)res != end_hex - offset) {
    fprintf(stderr, "BN_hex2bn(dh_pub) failed with errors: %d\n", res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 1;
  }

  return 0;
}

int parse_msg_encrypt(char *buf, size_t size_buf, void *encrypt_data,
                      size_t *p_len_encrypt_data, unsigned char *iv_key,
                      int (*cb_ssl_errors)(const char *str, size_t len,
                                           void *u)) {

  errno_t err;
  int res;

  unsigned char *tmp_iv_key;
  unsigned char *tmp_encrypt_data;
  size_t out_size_iv = 0;
  size_t out_size_encrypt_data = 0;

  size_t offset = 0;
  size_t end_hex = 0;

  res = strncmp(buf + offset, "iv ", min(sizeof("iv ") - 1, size_buf - offset));
  if (res != 0) {
    fprintf(stderr, "Message not have iv\n");
    return 1;
  }
  offset += sizeof("iv ") - 1;
  for (end_hex = offset; end_hex < size_buf - 1 && buf[end_hex] != ' ';
       end_hex += 1) {
    if ((buf[end_hex] >= '0' && buf[end_hex] <= '9') ||
        (buf[end_hex] >= 'a' && buf[end_hex] <= 'f') ||
        (buf[end_hex] >= 'A' && buf[end_hex] <= 'F')) {

    } else {
      fprintf(stderr, "Message have not hex iv\n");
      return 1;
    }
  }
  if (buf[end_hex] != ' ') {
    fprintf(stderr, "Message have invalid iv\n");
    return 1;
  }
  buf[end_hex] = 0;

  out_size_iv = 0;
  tmp_iv_key = hexstr2buf(buf + offset, &out_size_iv);
  if (tmp_iv_key == NULL) {
    fprintf(stderr, "OPENSSL_hexstr2buf(iv_key) failed with errors: %d\n", res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 1;
  }
  memset(iv_key, 0, AES_BLOCK_SIZE);
  err = memcpy_s(iv_key, AES_BLOCK_SIZE, tmp_iv_key, (size_t)out_size_iv);
  OPENSSL_free(tmp_iv_key);
  tmp_iv_key = NULL;
  if (err != 0) {
    fprintf(stderr, "memcpy_s(iv_key) failed with errors: %d\n", err);
    return 1;
  }
  offset = end_hex + 1;

  res = strncmp(buf + offset, "data ",
                min(sizeof("data ") - 1, size_buf - offset));
  if (res != 0) {
    fprintf(stderr, "Message not have data\n");
    return 1;
  }
  offset += sizeof("data ") - 1;
  for (end_hex = offset; end_hex < size_buf - 1; end_hex += 1) {
    if ((buf[end_hex] >= '0' && buf[end_hex] <= '9') ||
        (buf[end_hex] >= 'a' && buf[end_hex] <= 'f') ||
        (buf[end_hex] >= 'A' && buf[end_hex] <= 'F')) {

    } else {
      fprintf(stderr, "Message have not hex data\n");
      return 1;
    }
  }
  if (buf[end_hex] != '\n') {
    fprintf(stderr, "Message have invalid data\n");
    return 1;
  }
  buf[end_hex] = 0;
  out_size_encrypt_data = 0;
  tmp_encrypt_data = hexstr2buf(buf + offset, &out_size_encrypt_data);
  if (tmp_encrypt_data == NULL) {
    fprintf(stderr, "OPENSSL_hexstr2buf(encrypt_data) failed with errors: %d\n",
            res);
    if (cb_ssl_errors != NULL) {
      ERR_print_errors_cb(cb_ssl_errors, NULL);
    }
    return 1;
  }
  err = memcpy_s(encrypt_data, *p_len_encrypt_data, tmp_encrypt_data,
                 (size_t)out_size_encrypt_data);
  OPENSSL_free(tmp_encrypt_data);
  tmp_encrypt_data = NULL;
  if (err != 0) {
    fprintf(stderr, "memcpy_s(encrypt_data) failed with errors: %d\n", err);
    return 1;
  }

  *p_len_encrypt_data = (size_t)out_size_encrypt_data;
  return 0;
}

int parse_msg_time(char *buf, size_t size_buf, uint64_t *p_time) {
  int res;

  size_t offset = 0;
  size_t end_hex = 0;

  res = strncmp(buf + offset, "time ",
                min(sizeof("time ") - 1, size_buf - offset));
  if (res != 0) {
    fprintf(stderr, "Message not have time\n");
    return 1;
  }
  offset += sizeof("time ") - 1;
  for (end_hex = offset; end_hex < size_buf - 1 && buf[end_hex] != '\n';
       end_hex += 1) {
    if ((buf[end_hex] >= '0' && buf[end_hex] <= '9') ||
        (buf[end_hex] >= 'a' && buf[end_hex] <= 'f') ||
        (buf[end_hex] >= 'A' && buf[end_hex] <= 'F')) {

    } else {
      fprintf(stderr, "Message have not hex time\n");
      return 1;
    }
  }
  if (buf[end_hex] != '\n') {
    fprintf(stderr, "Message have invalid time\n");
    return 1;
  }
  buf[end_hex] = 0;

  *p_time = 0;
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
  res = sscanf(buf + offset, "%" PRIX64, p_time);
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
  if (res != 1) {
    fprintf(stderr, "sscanf_s failed with errors\n");
    return 1;
  }

  return 0;
}