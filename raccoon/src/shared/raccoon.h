#ifndef RACCOON_H
#define RACCOON_H

#include <openssl/ssl.h>

typedef enum _msg_type {
  mt_random,
  mt_pub,
  mt_params,
  mt_data,
  mt_time,
  mt_error,
  mt_close,
  mt_unknown = 127
} msg_type;

msg_type get_msg_type(const char *buf, size_t size_buf);

size_t msg_random(const unsigned char *random, size_t size_random, char *buf,
                  size_t size_buf,
                  int (*cb_ssl_errors)(const char *str, size_t len, void *u));

size_t msg_params(const BIGNUM *dh_p, const BIGNUM *dh_g, const BIGNUM *dh_pub,
                  char *buf, size_t size_buf,
                  int (*cb_ssl_errors)(const char *str, size_t len, void *u));

size_t msg_pub(const BIGNUM *dh_pub, char *buf, size_t size_buf,
               int (*cb_ssl_errors)(const char *str, size_t len, void *u));

size_t msg_encrypt(const void *encrypt_data, size_t len_encrypt_data,
                   const unsigned char *iv_key, char *buf, size_t size_buf,
                   int (*cb_ssl_errors)(const char *str, size_t len, void *u));

size_t msg_time(uint64_t time, char *buf, size_t size_buf);

size_t msg_close(char *buf, size_t size_buf);

int parse_msg_random(char *buf, size_t size_buf, unsigned char *random,
                     size_t size_random,
                     int (*cb_ssl_errors)(const char *str, size_t len,
                                          void *u));

int parse_msg_params(char *buf, size_t size_buf, BIGNUM *dh_p, BIGNUM *dh_g,
                     BIGNUM *dh_pub_s,
                     int (*cb_ssl_errors)(const char *str, size_t len,
                                          void *u));

int parse_msg_pub(char *buf, size_t size_buf, BIGNUM *dh_pub,
                  int (*cb_ssl_errors)(const char *str, size_t len, void *u));

int parse_msg_encrypt(char *buf, size_t size_buf, void *encrypt_data,
                      size_t *p_len_encrypt_data, unsigned char *iv_key,
                      int (*cb_ssl_errors)(const char *str, size_t len,
                                           void *u));

int parse_msg_time(char *buf, size_t size_buf, uint64_t *p_time);

#endif // RACCOON_H