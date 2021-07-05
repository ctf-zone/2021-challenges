#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#if defined(WIN32)
#include <openssl/applink.c>
#endif
#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "raccoon.h"
#include "socket_cross.h"
#include "thread_cross.h"
#include "net_utils.h"
#include "ssl_utils.h"
#include "cross.h"

#define DEFAULT_PORT "8444"
#define SERVER_HOST "127.0.0.1"
#define MSG_SEND "raccoon"

#define DH_PRIV_KEY "1FB3B9D8A097BE72EAD5C1DB2D7519BD9854C2D40BE78C7FD88E0C4D22239E67594BA8934FCB3E471F757472A02D7C815FFA4099BB584F0722650892567781AD7A82049D869D2E8462E7A25A252726ACD168FC0198015A1B610A5FC71280E25652C7E63935F5A9F298E931FC001247174E060E0CC5316A00"

static int cb_ssl_errors(const char *str, size_t len, void *bp) {
  UNREFERENCED_PARAMETER(bp);

  if (len > INT16_MAX) {
    return -1;
  }
  fprintf(stderr, "\t%.*s\n", (int)len, str);
  return 1;
}

typedef enum _client_state {
  cstate_send_random_client,
  cstate_read_random_server,
  cstate_read_params_server,
  cstate_send_pub_client,
  cstate_read_time,
  cstate_send_data,
  cstate_recv_data,
  cstate_send_close,
  cstate_close,
  cstate_error = 127
} client_state;

int raccon_client(SOCKET client_socket) {
  int exit_code = 0;
  errno_t err;
  int res;
  void *p_res;

  client_state state = cstate_send_random_client;
  char unsigned server_random[SSL3_RANDOM_SIZE],
      client_random[SSL3_RANDOM_SIZE];
  unsigned char seed_sc[SSL3_RANDOM_SIZE * 2];
  char msg_client[DEFAULT_BUFLEN], msg_server[DEFAULT_BUFLEN];
  size_t len_msg_client = 0, len_msg_server = 0, len_data_server = 0;

  unsigned char data[DEFAULT_BUFLEN / 4], encrypt_data[DEFAULT_BUFLEN / 4];
  size_t len_data = 0, len_encrypt_data = 0;

  DH *dh = NULL;
  BIGNUM *dh_g = NULL, *dh_p = NULL, *dh_pub_s = NULL;
  const BIGNUM *dh_pub_c = NULL;
  int size_pms = 0;
  unsigned char *pms = NULL;
  unsigned char master_key[SHA256_DIGEST_LENGTH], iv_key[AES_BLOCK_SIZE];
  uint64_t t_time;
  EVP_CIPHER_CTX *ctx_evp_encrypt = NULL, *ctx_evp_decrypt = NULL;

  res = RAND_bytes(client_random, (int)sizeof(client_random));
  if (res != 1) {
    fprintf(stderr, "RAND_bytes_ex failed with errors: %d\n", res);
    ERR_print_errors_cb(cb_ssl_errors, NULL);
    exit_code = 1;
    goto error0;
  }

  dh = DH_new();
  if (dh == NULL) {
    fprintf(stderr, "DH_new() failed with errors\n");
    ERR_print_errors_cb(cb_ssl_errors, NULL);
    goto error1;
  }

  ctx_evp_encrypt = EVP_CIPHER_CTX_new();
  if (ctx_evp_encrypt == NULL) {
    fprintf(stderr, "BN_new(encrypt) failed with errors\n");
    ERR_print_errors_cb(cb_ssl_errors, NULL);
    goto error2;
  }
  ctx_evp_decrypt = EVP_CIPHER_CTX_new();
  if (ctx_evp_decrypt == NULL) {
    fprintf(stderr, "EVP_CIPHER_CTX_new(decrypt) failed with errors\n");
    ERR_print_errors_cb(cb_ssl_errors, NULL);
    goto error3;
  }

  while (state != cstate_error && state != cstate_close) {
    switch (state) {
    case cstate_send_random_client:
      len_msg_client =
          msg_random(client_random, sizeof(client_random), msg_client,
                     sizeof(msg_client), cb_ssl_errors);
      if (len_msg_client == 0) {
        state = cstate_error;
        break;
      }
      res = send_all(client_socket, msg_client, len_msg_client);
      if (res != 0) {
        fprintf(stderr, "Can't send client random\n");
        state = cstate_error;
        break;
      }
      state = cstate_read_random_server;
      break;
    case cstate_read_random_server:
      res = recv_msg(client_socket, msg_server, sizeof(msg_server),
                     &len_msg_server, &len_data_server);
      if (res != 0) {
        fprintf(stderr, "Can't recv server random\n");
        state = cstate_error;
        break;
      }
      res = parse_msg_random(msg_server, len_msg_server, server_random,
                             sizeof(server_random), cb_ssl_errors);
      if (res != 0) {
        fprintf(stderr, "Can't parse server random\n");
        state = cstate_error;
        break;
      }

      err = memcpy_s(seed_sc, sizeof(seed_sc), server_random,
                     sizeof(server_random));
      if (err == 0) {
        err = memcpy_s(seed_sc + sizeof(server_random),
                       sizeof(seed_sc) - sizeof(server_random), client_random,
                       sizeof(client_random));
      }
      if (err != 0) {
        fprintf(stderr, "memcpy_s(seed) failed with errors: %d\n", err);
        state = cstate_error;
        break;
      }

      err =
          memcpy_s(msg_server, sizeof(msg_server), msg_server + len_msg_server,
                   len_data_server - len_msg_server);
      if (err != 0) {
        fprintf(stderr, "memcpy_s failed with errors: %d\n", err);
        state = cstate_error;
        break;
      }
      len_data_server = len_data_server - len_msg_server;
      len_msg_server = 0;
      state = cstate_read_params_server;
      break;
    case cstate_read_params_server:
      res = recv_msg(client_socket, msg_server, sizeof(msg_server),
                     &len_msg_server, &len_data_server);
      if (res != 0) {
        fprintf(stderr, "Can't recv server params\n");
        state = cstate_error;
        break;
      }
      dh_pub_s = BN_new();
      if (dh_pub_s == NULL) {
        fprintf(stderr, "BN_new(dh_pub_s) failed with errors\n");
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        state = cstate_error;
        break;
      }
      dh_g = BN_new();
      if (dh_g == NULL) {
        fprintf(stderr, "BN_new(dh_g) failed with errors\n");
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        BN_free(dh_pub_s);
        dh_pub_s = NULL;
        state = cstate_error;
        break;
      }
      dh_p = BN_new();
      if (dh_p == NULL) {
        fprintf(stderr, "BN_new(dh_p) failed with errors\n");
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        BN_free(dh_pub_s);
        BN_free(dh_g);
        dh_pub_s = NULL;
        dh_g = NULL;
        state = cstate_error;
        break;
      }
      res = parse_msg_params(msg_server, len_msg_server, dh_p, dh_g, dh_pub_s,
                             cb_ssl_errors);
      if (res != 0) {
        fprintf(stderr, "Can't parse server params\n");
        BN_free(dh_pub_s);
        BN_free(dh_g);
        BN_free(dh_p);
        dh_pub_s = NULL;
        dh_g = NULL;
        dh_p = NULL;
        state = cstate_error;
        break;
      }
      res = DH_set0_pqg(dh, dh_p, NULL, dh_g);
      if (res != 1) {
        fprintf(stderr, "DH_get0_key(dh_pub_c) failed with errors\n");
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        BN_free(dh_pub_s);
        BN_free(dh_g);
        BN_free(dh_p);
        dh_g = NULL;
        dh_p = NULL;
        dh_pub_s = NULL;
        state = cstate_error;
        break;
      }

      res = set_priv_key_DH(dh, DH_PRIV_KEY, cb_ssl_errors);
      if(res != 0) {
        fprintf(stderr, "set_priv_key_DH failed with errors\n");
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        BN_free(dh_pub_s);
        dh_pub_s = NULL;
        state = cstate_error;
        break;
      }
      res = DH_generate_key(dh);
      if (res != 1) {
        fprintf(stderr, "DH_generate_key failed with errors: %d\n", res);
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        BN_free(dh_pub_s);
        dh_pub_s = NULL;
        state = cstate_error;
        break;
      }
      size_pms = DH_size(dh);
      if (size_pms == 0) {
        fprintf(stderr, "DH_size failed with errors\n");
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        BN_free(dh_pub_s);
        dh_pub_s = NULL;
        state = cstate_error;
        break;
      }
      pms = OPENSSL_malloc((size_t)size_pms);
      if (pms == NULL) {
        fprintf(stderr, "OPENSSL_malloc(pms) failed with errors\n");
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        BN_free(dh_pub_s);
        dh_pub_s = NULL;
        state = cstate_error;
        break;
      }
      size_pms = DH_compute_key(pms, dh_pub_s, dh);
      if (size_pms == -1) {
        fprintf(stderr, "DH_compute_key failed with errors\n");
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        BN_free(dh_pub_s);
        OPENSSL_free(pms);
        dh_pub_s = NULL;
        pms = NULL;
        state = cstate_error;
        break;
      }

      BN_free(dh_pub_s);
      dh_pub_s = NULL;

      p_res = HMAC(EVP_sha256(), pms, size_pms, seed_sc, sizeof(seed_sc),
                   master_key, NULL);
      OPENSSL_free(pms);
      pms = NULL;
      if (p_res == NULL) {
        fprintf(stderr, "HMAC(master_key) failed with errors\n");
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        state = cstate_error;
        break;
      }

      err =
          memcpy_s(msg_server, sizeof(msg_server), msg_server + len_msg_server,
                   len_data_server - len_msg_server);
      if (err != 0) {
        fprintf(stderr, "memcpy_s failed with errors: %d\n", err);
        state = cstate_error;
        break;
      }
      len_data_server = len_data_server - len_msg_server;
      len_msg_server = 0;
      state = cstate_send_pub_client;
      break;
    case cstate_send_pub_client:
      dh_pub_c = NULL;
      DH_get0_key(dh, &dh_pub_c, NULL);
      if (dh_pub_c == NULL) {
        fprintf(stderr, "DH_get0_key(dh_pub_c) failed with errors\n");
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        state = cstate_error;
        break;
      }
      len_msg_client =
          msg_pub(dh_pub_c, msg_client, sizeof(msg_client), cb_ssl_errors);
      dh_pub_c = NULL;
      if (len_msg_client == 0) {
        state = cstate_error;
        break;
      }
      res = send_all(client_socket, msg_client, len_msg_client);
      if (res != 0) {
        fprintf(stderr, "Can't send client pub\n");
        state = cstate_error;
        break;
      }
      state = cstate_read_time;
      break;
    case cstate_read_time:
      res = recv_msg(client_socket, msg_server, sizeof(msg_server),
                     &len_msg_server, &len_data_server);
      if (res != 0) {
        fprintf(stderr, "Can't recv time\n");
        state = cstate_error;
        break;
      }
      t_time = 0;
      res = parse_msg_time(msg_server, len_msg_server, &t_time);
      if (res != 0) {
        fprintf(stderr, "Can't parse time\n");
        state = cstate_error;
        break;
      }
      printf("Time:%" PRIu64 "\n", t_time);
      err =
          memcpy_s(msg_server, sizeof(msg_server), msg_server + len_msg_server,
                   len_data_server - len_msg_server);
      if (err != 0) {
        fprintf(stderr, "memcpy_s failed with errors: %d\n", err);
        state = cstate_error;
        break;
      }
      len_data_server = len_data_server - len_msg_server;
      len_msg_server = 0;
      state = cstate_send_data;
      break;
    case cstate_send_data:
      res = RAND_bytes(iv_key, sizeof(iv_key));
      if (res != 1) {
        fprintf(stderr, "RAND_bytes(iv_key) failed with errors: %d\n", res);
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        state = cstate_error;
        break;
      }

      len_encrypt_data = sizeof(encrypt_data);
      res = encrypt_raccoon(ctx_evp_encrypt, master_key, iv_key,
                            (const unsigned char *)MSG_SEND,
                            sizeof(MSG_SEND) - 1, encrypt_data,
                            &len_encrypt_data, cb_ssl_errors);
      if (res != 0) {
        fprintf(stderr, "encrypt failed with errors: %d\n", res);
        state = cstate_error;
        break;
      }

      len_msg_client =
          msg_encrypt(encrypt_data, len_encrypt_data, iv_key, msg_client,
                      sizeof(msg_client), cb_ssl_errors);

      res = send_all(client_socket, msg_client, len_msg_client);
      if (res != 0) {
        fprintf(stderr, "Can't send data\n");
        state = cstate_error;
        break;
      }
      state = cstate_recv_data;
      break;
    case cstate_recv_data:
      res = recv_msg(client_socket, msg_server, sizeof(msg_server),
                     &len_msg_server, &len_data_server);
      if (res != 0) {
        fprintf(stderr, "Can't recv server params\n");
        state = cstate_error;
        break;
      }
      len_encrypt_data = sizeof(encrypt_data);
      res = parse_msg_encrypt(msg_server, len_msg_server, encrypt_data,
                              &len_encrypt_data, iv_key, cb_ssl_errors);
      if (res != 0) {
        fprintf(stderr, "Can't parse encrypt msg\n");
        state = cstate_error;
        break;
      }

      len_data = sizeof(data);
      res = decrypt_raccoon(ctx_evp_decrypt, master_key, iv_key, encrypt_data,
                            len_encrypt_data, data, &len_data, cb_ssl_errors);
      if (res != 0) {
        fprintf(stderr, "decrypt failed with errors: %d\n", res);
        state = cstate_error;
        break;
      }
      len_data = strnlen_s((const char *)data, len_data);
      printf("Recv size:%" PRIuPTR ", data:%.*s\n", len_data, (int)len_data,
             data);

      err =
          memcpy_s(msg_server, sizeof(msg_server), msg_server + len_msg_server,
                   len_data_server - len_msg_server);
      if (err != 0) {
        fprintf(stderr, "memcpy_s failed with errors: %d\n", err);
        state = cstate_error;
        break;
      }
      len_data_server = len_data_server - len_msg_server;
      len_msg_server = 0;
      state = cstate_send_close;
      break;
    case cstate_send_close:
      len_msg_client = msg_close(msg_client, sizeof(msg_client));
      res = send_all(client_socket, msg_client, len_msg_client);
      if (res != 0) {
        fprintf(stderr, "Can't send client close\n");
        state = cstate_error;
        break;
      }
      state = cstate_close;
      break;
    default:
      fprintf(stderr, "Unknown client state %d\n", state);
      state = cstate_error;
      break;
    }
  }
  if (state == cstate_close) {
    exit_code = 0;
  } else {
    fprintf(stderr, "Client closed on error state %d\n", state);
    exit_code = 1;
  }

error3:
  EVP_CIPHER_CTX_free(ctx_evp_decrypt);
error2:
  EVP_CIPHER_CTX_free(ctx_evp_encrypt);
error1:
  DH_free(dh);
error0:
  return exit_code;
}

int main() {

#if defined(WIN32)
  WSADATA wsaData;
#endif

  char str_ip_addr[128] = {0};
  int exit_code = 0;
  int res;

  struct addrinfo *addr_result = NULL;
  struct addrinfo addr_hints = {0};

  SOCKET client_socket = INVALID_SOCKET;
  char recvbuf[DEFAULT_BUFLEN];
  int recvbuflen = DEFAULT_BUFLEN;

  printf("Raccoon client\n");

#if defined(WIN32)
  res = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (res != 0) {
    fprintf(stderr, "WSAStartup failed with error: %d\n", res);
    exit_code = 1;
    goto error0;
  }
#endif

  res = OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
  if (res != 1) {
    fprintf(stderr, "OPENSSL_init_ssl failed with error: %d\n", res);
    exit_code = 3;
    goto error1;
  }

  addr_hints.ai_family = AF_INET;
  addr_hints.ai_socktype = SOCK_STREAM;
  addr_hints.ai_protocol = IPPROTO_TCP;
  addr_hints.ai_flags = AI_PASSIVE;

  res = getaddrinfo(SERVER_HOST, DEFAULT_PORT, &addr_hints, &addr_result);
  if (res != 0) {
    fprintf(stderr, "getaddrinfo failed with error: %d\n", res);
    exit_code = 1;
    goto error1;
  }

  get_ip_str(addr_result->ai_addr, str_ip_addr, sizeof(str_ip_addr));
  printf("Server: %s:%d\n", str_ip_addr, get_port(addr_result->ai_addr));
  client_socket = socket(addr_result->ai_family, addr_result->ai_socktype,
                         addr_result->ai_protocol);
  if (client_socket == INVALID_SOCKET) {
    fprintf(stderr, "socket failed with error: %d\n", get_socket_error());
    exit_code = 1;
    goto error2;
  }

  res = connect(client_socket, addr_result->ai_addr,
                (int)addr_result->ai_addrlen);
  if (res == SOCKET_ERROR) {
    fprintf(stderr, "bind failed with error: %d\n", get_socket_error());
    exit_code = 1;
    goto error3;
  }

  raccon_client(client_socket);

  res = shutdown(client_socket, SD_SEND);
  if (res == SOCKET_ERROR) {
    printf("shutdown failed with error: %d\n", get_socket_error());
    exit_code = 1;
    goto error3;
  }

  do {
    recvbuflen = sizeof(recvbuf);
    res = recv(client_socket, recvbuf, recvbuflen, 0);
    if (res > 0) {
      printf("Bytes received: %d\n", res);
    } else if (res == 0) {
      printf("Connection closed\n");
    } else {
      printf("recv failed with error: %d\n", get_socket_error());
    }
  } while (res > 0);

error3:
  closesocket(client_socket);
error2:
  freeaddrinfo(addr_result);
error1:
#if defined(WIN32)
  WSACleanup();
error0:
#endif
  return exit_code;
}
