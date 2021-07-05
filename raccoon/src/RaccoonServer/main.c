#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#if defined(WIN32)
#include <openssl/applink.c>
#endif
#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include "raccoon.h"
#include "socket_cross.h"
#include "thread_cross.h"
#include "net_utils.h"
#include "ssl_utils.h"
#include "cross.h"

#define DEFAULT_PORT "8444"
#define SERVER_HOST "0.0.0.0"

#define DH_PRIV_KEY "***********"

typedef struct _connection_t {
  SOCKET socket;
  struct sockaddr sockaddr;
  socklen_t sockaddr_size;
  DH *dh;
} connection_t;

int raccoon_server(SOCKET client_socket, DH *dh);
void raccoon_server_th(connection_t *p_client_connection);

static int cb_ssl_errors(const char *str, size_t len, void *bp) {
  UNREFERENCED_PARAMETER(bp);

  if (len > INT16_MAX) {
    return -1;
  }
  fprintf(stderr, "\t%.*s\n", (int)len, str);
  return 1;
}

int main() {
  char str_ip_addr[128] = {0};
  int exit_code = 0;
  int res;
  errno_t err;

  DH *dh = NULL;
  FILE *paramfile = NULL;

#if defined(WIN32)
  WSADATA wsaData;
#endif

  struct addrinfo *addr_result = NULL;
  struct addrinfo addr_hints = {0};
  SOCKET listen_socket = INVALID_SOCKET;

  printf("Raccoon server\n");

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

  err = fopen_s(&paramfile, "dhparams.pem", "r");
  if (err == 0 && paramfile != NULL) {
    dh = PEM_read_DHparams(paramfile, NULL, NULL, NULL);
    fclose(paramfile);
    if (dh == NULL) {
      fprintf(stderr, "PEM_read_DHparams failed with errors\n");
      ERR_print_errors_cb(cb_ssl_errors, NULL);
      goto error1;
    }
  } else {
    fprintf(stderr, "fopen(dhparams.pem) failed with errors: %d\n", err);
    goto error1;
  }

  res = set_priv_key_DH(dh, DH_PRIV_KEY, cb_ssl_errors);
  if (res != 0) {
    fprintf(stderr, "set_priv_key_DH failed with errors: %d\n", res);
    goto error2;
  }

  res = DH_generate_key(dh);
  if (res != 1) {
    fprintf(stderr, "DH_generate_key failed with errors: %d\n", res);
    ERR_print_errors_cb(cb_ssl_errors, NULL);
    goto error2;
  }

  print_DH(dh);

  addr_hints.ai_family = AF_INET;
  addr_hints.ai_socktype = SOCK_STREAM;
  addr_hints.ai_protocol = IPPROTO_TCP;
  addr_hints.ai_flags = AI_PASSIVE;

  res = getaddrinfo(NULL, DEFAULT_PORT, &addr_hints, &addr_result);
  if (res != 0) {
    fprintf(stderr, "getaddrinfo failed with error: %d\n", res);
    exit_code = 1;
    goto error2;
  }

  get_ip_str(addr_result->ai_addr, str_ip_addr, sizeof(str_ip_addr));
  printf("Server: %s:%d\n", str_ip_addr, get_port(addr_result->ai_addr));
  listen_socket = socket(addr_result->ai_family, addr_result->ai_socktype,
                         addr_result->ai_protocol);
  if (listen_socket == INVALID_SOCKET) {
    fprintf(stderr, "socket failed with error: %d\n", get_socket_error());
    exit_code = 1;
    goto error3;
  }

  res = bind(listen_socket, addr_result->ai_addr, (int)addr_result->ai_addrlen);
  if (res == SOCKET_ERROR) {
    fprintf(stderr, "bind failed with error: %d\n", get_socket_error());
    exit_code = 1;
    goto error4;
  }

  res = listen(listen_socket, SOMAXCONN);
  if (res == SOCKET_ERROR) {
    fprintf(stderr, "listen failed with error: %d\n", get_socket_error());
    exit_code = 1;
    goto error4;
  }

  while (true) {
    connection_t *p_client_connection = NULL;
    pthread_t thread;

    p_client_connection = malloc(sizeof(connection_t));
    if (p_client_connection == NULL) {
      fprintf(stderr, "malloc(client_connection) failed\n");
      continue;
    }
    p_client_connection->sockaddr_size =
        (int)sizeof(p_client_connection->sockaddr);
    p_client_connection->socket =
        accept(listen_socket, &p_client_connection->sockaddr,
               &p_client_connection->sockaddr_size);
    if (p_client_connection->socket == INVALID_SOCKET) {
      fprintf(stderr, "accept failed with error: %d\n", get_socket_error());
      free(p_client_connection);
      continue;
    }

    p_client_connection->dh = dh;
    res = begin_thread(&thread, (THREADFUNC)raccoon_server_th,
                       (void *)p_client_connection);
    if (res != 0) {
      fprintf(stderr, "pthread_create failed with error: %d\n", res);
      closesocket(p_client_connection->socket);
      free(p_client_connection);
      continue;
    }
    res = detach_thread(thread);
    if (res != 0) {
      fprintf(stderr, "pthread_detach failed with error: %d\n", res);
    }
  }

error4:
  closesocket(listen_socket);
error3:
  freeaddrinfo(addr_result);
error2:
  DH_free(dh);
error1:
#if defined(WIN32)
  WSACleanup();
error0:
#endif
  return exit_code;
}

void raccoon_server_th(connection_t *p_client_connection) {
  int res;
  char str_ip_addr[128] = {0};

  if (p_client_connection->sockaddr_size > 0) {
    get_ip_str(&p_client_connection->sockaddr, str_ip_addr,
               sizeof(str_ip_addr));
    // printf("[tid %u]Accept client: %s:%d\n", get_current_tid(), str_ip_addr,
    //       get_port(&p_client_connection->sockaddr));
  } else {
    // printf("[tid %u]Accept client: <<unkmown>>\n", get_current_tid());
  }

  raccoon_server(p_client_connection->socket, p_client_connection->dh);

  res = shutdown(p_client_connection->socket, SD_SEND);
  if (res == SOCKET_ERROR) {
    fprintf(stderr, "[tid %u]shutdown failed with error: %d\n",
            get_current_tid(), get_socket_error());
  }

  closesocket(p_client_connection->socket);
  free(p_client_connection);

  exit_thread();
}

typedef enum _server_state {
  sstate_start,
  sstate_wait_client_pub,
  sstate_established,
  sstate_close,
  sstate_error = 127
} server_state;

int raccoon_server(SOCKET client_socket, DH *dh) {
  int exit_code = 0;
  errno_t err;
  void *p_res;
  int res;

  server_state state = sstate_start;
  bool have_client_random = false;
  bool have_client_pub = false;

  unsigned char server_random[SSL3_RANDOM_SIZE],
      client_random[SSL3_RANDOM_SIZE];
  unsigned char seed_sc[SSL3_RANDOM_SIZE * 2];
  char msg_client[DEFAULT_BUFLEN], msg_server[DEFAULT_BUFLEN];
  size_t len_msg_client = 0, len_data_client = 0, len_msg_server = 0;

  unsigned char data[DEFAULT_BUFLEN / 4], encrypt_data[DEFAULT_BUFLEN / 4];
  size_t len_data = 0, len_encrypt_data = 0;

  const BIGNUM *dh_g = NULL, *dh_p = NULL, *dh_pub_s = NULL;
  BIGNUM *dh_pub_c = NULL;
  int size_tmp_pms = 0;
  int size_pms = 0;
  unsigned char *pms = NULL;
  unsigned char master_key[SHA256_DIGEST_LENGTH], iv_key[AES_BLOCK_SIZE];
  uint64_t t_delta;
  EVP_CIPHER_CTX *ctx_evp_encrypt = NULL, *ctx_evp_decrypt = NULL;

  res = RAND_bytes(server_random, (int)sizeof(server_random));
  if (res != 1) {
    fprintf(stderr, "RAND_bytes failed with errors: %d\n", res);
    ERR_print_errors_cb(cb_ssl_errors, NULL);
    exit_code = 1;
    goto error0;
  }

  ctx_evp_encrypt = EVP_CIPHER_CTX_new();
  if (ctx_evp_encrypt == NULL) {
    fprintf(stderr, "BN_new(encrypt) failed with errors\n");
    ERR_print_errors_cb(cb_ssl_errors, NULL);
    goto error1;
  }
  ctx_evp_decrypt = EVP_CIPHER_CTX_new();
  if (ctx_evp_decrypt == NULL) {
    fprintf(stderr, "EVP_CIPHER_CTX_new(decrypt) failed with errors\n");
    ERR_print_errors_cb(cb_ssl_errors, NULL);
    goto error2;
  }

  while (state != sstate_error && state != sstate_close) {
    msg_type m_type = mt_unknown;

    res = recv_msg(client_socket, msg_client, sizeof(msg_client),
                   &len_msg_client, &len_data_client);
    if (res == 1) {
      state = sstate_close;
      break;
    } else if (res != 0) {
      fprintf(stderr, "[tid %u]Can't recv client\n", get_current_tid());
      state = sstate_error;
      break;
    }

    m_type = get_msg_type(msg_client, len_msg_client);

    if (m_type == mt_random) {
      // parse random
      res = parse_msg_random(msg_client, len_msg_client, client_random,
                             sizeof(client_random), cb_ssl_errors);
      if (res != 0) {
        fprintf(stderr, "Can't parse client random\n");
        state = sstate_error;
        continue;
      }
      err =
          memcpy_s(msg_client, sizeof(msg_client), msg_client + len_msg_client,
                   len_data_client - len_msg_client);
      if (err != 0) {
        fprintf(stderr, "memcpy_s failed with errors: %d\n", err);
        state = sstate_error;
        continue;
      }
      len_data_client = len_data_client - len_msg_client;
      len_msg_client = 0;

      err = memcpy_s(seed_sc, sizeof(seed_sc), server_random,
                     sizeof(server_random));
      if (err == 0) {
        err = memcpy_s(seed_sc + sizeof(server_random),
                       sizeof(seed_sc) - sizeof(server_random), client_random,
                       sizeof(client_random));
      }
      if (err != 0) {
        fprintf(stderr, "memcpy_s(seed) failed with errors: %d\n", err);
        state = sstate_error;
        continue;
      }

      if (state == sstate_start) {
        // send random
        len_msg_server =
            msg_random(server_random, sizeof(server_random), msg_server,
                       sizeof(msg_server), cb_ssl_errors);
        if (len_msg_server == 0) {
          state = sstate_error;
          continue;
        }
        res = send_all(client_socket, msg_server, len_msg_server);
        if (res != 0) {
          fprintf(stderr, "Can't send server random\n");
          state = sstate_error;
          continue;
        }

        // send params
        DH_get0_pqg(dh, &dh_p, NULL, &dh_g);
        DH_get0_key(dh, &dh_pub_s, NULL);

        len_msg_server = msg_params(dh_p, dh_g, dh_pub_s, msg_server,
                                    sizeof(msg_server), cb_ssl_errors);
        dh_p = NULL;
        dh_g = NULL;
        dh_pub_s = NULL;
        if (len_msg_server == 0) {
          state = sstate_error;
          continue;
        }
        res = send_all(client_socket, msg_server, len_msg_server);
        if (res != 0) {
          fprintf(stderr, "Can't send server random\n");
          state = sstate_error;
          continue;
        }
        state = sstate_wait_client_pub;
      }
      have_client_random = true;
    } else if (m_type == mt_pub) {
      if (have_client_random == false) {
        fprintf(stderr, "Client sent public key without random\n");
        state = sstate_error;
        continue;
      }

      dh_pub_c = BN_new();
      if (dh_pub_c == NULL) {
        fprintf(stderr, "BN_new(dh_pub_c) failed with errors\n");
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        state = sstate_error;
        continue;
      }

      res = parse_msg_pub(msg_client, len_msg_client, dh_pub_c, cb_ssl_errors);
      if (res != 0) {
        fprintf(stderr, "Can't parse client pub\n");
        BN_free(dh_pub_c);
        dh_pub_c = NULL;
        state = sstate_error;
        continue;
      }
      err =
          memcpy_s(msg_client, sizeof(msg_client), msg_client + len_msg_client,
                   len_data_client - len_msg_client);
      if (err != 0) {
        fprintf(stderr, "memcpy_s failed with errors: %d\n", err);
        state = sstate_error;
        continue;
      }
      len_data_client = len_data_client - len_msg_client;
      len_msg_client = 0;

      size_tmp_pms = DH_size(dh);
      if (size_tmp_pms == 0) {
        fprintf(stderr, "DH_size failed with errors\n");
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        BN_free(dh_pub_c);
        dh_pub_c = NULL;
        state = sstate_error;
        continue;
      }
      pms = OPENSSL_malloc((size_t)size_tmp_pms);
      if (pms == NULL) {
        fprintf(stderr, "OPENSSL_malloc(pms) failed with errors\n");
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        BN_free(dh_pub_c);
        dh_pub_c = NULL;
        state = sstate_error;
        continue;
      }
      size_pms = DH_compute_key(pms, dh_pub_c, dh);
      if (size_pms == -1) {
        fprintf(stderr, "DH_compute_key failed with errors\n");
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        BN_free(dh_pub_c);
        OPENSSL_free(pms);
        dh_pub_c = NULL;
        pms = NULL;
        state = sstate_error;
        continue;
      }

      BN_free(dh_pub_c);
      dh_pub_c = NULL;

      t_delta = 0;
      p_res = HMAC_with_time(EVP_sha256(), pms, size_pms, seed_sc,
                             sizeof(seed_sc), master_key, NULL, &t_delta);
      OPENSSL_free(pms);
      pms = NULL;
      if (p_res == NULL) {
        fprintf(stderr, "HMAC(master_key) failed with errors\n");
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        state = sstate_error;
        continue;
      }

      // send time
      len_msg_server = msg_time(t_delta, msg_server, sizeof(msg_server));
      if (len_msg_server == 0) {
        state = sstate_error;
        continue;
      }
      res = send_all(client_socket, msg_server, len_msg_server);
      if (res != 0) {
        fprintf(stderr, "Can't send hmac time\n");
        state = sstate_error;
        continue;
      }

      if (state == sstate_wait_client_pub) {
        state = sstate_established;
      }
      have_client_pub = true;
    } else if (m_type == mt_data) {
      if (have_client_pub == false || have_client_random == false) {
        fprintf(stderr, "Client sent data without random or pub key\n");
        state = sstate_error;
        continue;
      }
      // recv data
      len_encrypt_data = sizeof(encrypt_data);
      res = parse_msg_encrypt(msg_client, len_msg_client, encrypt_data,
                              &len_encrypt_data, iv_key, cb_ssl_errors);
      if (res != 0) {
        fprintf(stderr, "Can't parse encrypt msg\n");
        state = sstate_error;
        continue;
      }
      err =
          memcpy_s(msg_client, sizeof(msg_client), msg_client + len_msg_client,
                   len_data_client - len_msg_client);
      if (err != 0) {
        fprintf(stderr, "memcpy_s failed with errors: %d\n", err);
        state = sstate_error;
        continue;
      }
      len_data_client = len_data_client - len_msg_client;
      len_msg_client = 0;

      len_data = sizeof(data);
      res = decrypt_raccoon(ctx_evp_decrypt, master_key, iv_key, encrypt_data,
                            len_encrypt_data, data, &len_data, cb_ssl_errors);
      if (res != 0) {
        fprintf(stderr, "decrypt failed with errors: %d\n", res);
        state = sstate_error;
        continue;
      }
      len_data = strnlen_s((const char *)data, len_data);

      // send data
      if (len_data + 6 < sizeof(data)) {
        err = memmove_s(data + 3, sizeof(data) - 3, data, len_data);
        if (err != 0) {
          fprintf(stderr, "memcpy_s failed with errors: %d\n", err);
          state = sstate_error;
          continue;
        }
        len_data += 3;
        err = memcpy_s(data, sizeof(data), "+++", 3);
        if (err != 0) {
          fprintf(stderr, "memcpy_s failed with errors: %d\n", err);
          state = sstate_error;
          continue;
        }
        err = memcpy_s(data + len_data, sizeof(data) - len_data, "+++", 3);
        if (err != 0) {
          fprintf(stderr, "memcpy_s failed with errors: %d\n", err);
          state = sstate_error;
          continue;
        }
        len_data += 3;
      } else if (len_data > 6) {
        err = memcpy_s(data, sizeof(data), "+++", 3);
        if (err != 0) {
          fprintf(stderr, "memcpy_s failed with errors: %d\n", err);
          state = sstate_error;
          continue;
        }
        err = memcpy_s(data + len_data - 3, sizeof(data) - len_data - 3, "+++",
                       3);
        if (err != 0) {
          fprintf(stderr, "memcpy_s failed with errors: %d\n", err);
          state = sstate_error;
          continue;
        }
      }

      res = RAND_bytes(iv_key, sizeof(iv_key));
      if (res != 1) {
        fprintf(stderr, "RAND_bytes(iv_key) failed with errors: %d\n", res);
        ERR_print_errors_cb(cb_ssl_errors, NULL);
        state = sstate_error;
        continue;
      }

      len_encrypt_data = sizeof(encrypt_data);
      res = encrypt_raccoon(ctx_evp_encrypt, master_key, iv_key, data, len_data,
                            encrypt_data, &len_encrypt_data, cb_ssl_errors);
      if (res != 0) {
        fprintf(stderr, "encrypt failed with errors: %d\n", res);
        state = sstate_error;
        continue;
      }

      len_msg_server =
          msg_encrypt(encrypt_data, len_encrypt_data, iv_key, msg_server,
                      sizeof(msg_server), cb_ssl_errors);

      res = send_all(client_socket, msg_server, len_msg_server);
      if (res != 0) {
        fprintf(stderr, "Can't send data\n");
        state = sstate_error;
        continue;
      }
    } else if (m_type == mt_close) {
      state = sstate_close;
      continue;
    } else if (m_type == mt_error) {
      state = sstate_error;
      continue;
    } else {
      fprintf(stderr, "Unknown msg_type %d\n", state);
      state = sstate_error;
      continue;
    }
  }

  if (state == sstate_close) {
    // fprintf(stderr, "[tid %u]Server closed\n", get_current_tid());
    exit_code = 0;
  } else {
    fprintf(stderr, "[tid %u]Server closed on error state %d\n",
            get_current_tid(), state);
    exit_code = 1;
  }

error2:
  EVP_CIPHER_CTX_free(ctx_evp_decrypt);
error1:
  EVP_CIPHER_CTX_free(ctx_evp_encrypt);
error0:
  return exit_code;
}
