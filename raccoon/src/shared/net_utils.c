#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "cross.h"
#include "socket_cross.h"
#include "thread_cross.h"

int get_port(const struct sockaddr *sa) {
  switch (sa->sa_family) {
  case AF_INET: {
    struct sockaddr_in *addr_in = (struct sockaddr_in *)sa;
    return (int)htons(addr_in->sin_port);
  }
  case AF_INET6: {
    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)sa;
    return (int)htons(addr_in6->sin6_port);
  }
  default:
    return -1;
  }
}

char *get_ip_str(const struct sockaddr *sa, char *s, socklen_t maxlen) {
  char const *out = NULL;
  switch (sa->sa_family) {
  case AF_INET: {
    struct sockaddr_in *addr_in = (struct sockaddr_in *)sa;
    out = inet_ntop(AF_INET, &(addr_in->sin_addr), s, maxlen);
    if (out == NULL) {
      fprintf(stderr, "inet_ntop(AF_INET) failed with error: %d\n",
              get_socket_error());
      strcpy_s(s, maxlen, "Fail(AF_INET)");
    }
    break;
  }
  case AF_INET6: {
    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)sa;
    out = inet_ntop(AF_INET6, &(addr_in6->sin6_addr), s, maxlen);
    if (out == NULL) {
      fprintf(stderr, "inet_ntop(AF_INET6) failed with error: %d\n",
              get_socket_error());
      strcpy_s(s, maxlen, "Fail(AF_INET6)");
    }
    break;
  }
  default:
    strcpy_s(s, maxlen, "Unknown AF");
    break;
  }
  return s;
}

int send_all(SOCKET client_socket, const char *buf, size_t buflen) {
  int res;
  int exit_code = 0;

  size_t send_len = 0;

  while (send_len < buflen) {
    int batch_size = 0;
    batch_size = (int)min(1024, buflen - send_len);
    res = send(client_socket, buf + send_len, batch_size, 0);
    if (res != SOCKET_ERROR) {
      send_len += (size_t)res;
    } else {
      fprintf(stderr, "[tid %u]send failed with error: %d\n", get_current_tid(),
              get_socket_error());
      exit_code = 1;
      break;
    }
  }

  return exit_code;
}

int recv_msg(SOCKET client_socket, char *buf, size_t buflen, size_t *size_line,
             size_t *p_size_all_data) {
  int res;
  int exit_code = 0;
  char *p_end_line = NULL;

  p_end_line = memchr(buf, '\n', *p_size_all_data);
  if (p_end_line != NULL) {
    *size_line = p_end_line - buf + 1;
    return exit_code;
  }

  while (true) {
    int batch_size;
    batch_size = (int)min(buflen - *p_size_all_data, 1024);
    if (batch_size == 0) {
      fprintf(stderr, "[tid %u]more data\n", get_current_tid());
      exit_code = 2;
      break;
    }
    res = recv(client_socket, buf + *p_size_all_data, batch_size, 0);
    if (res > 0) {
      p_end_line = memchr(buf + *p_size_all_data, '\n', (size_t)res);
      *p_size_all_data += (size_t)res;
      if (p_end_line != NULL) {
        *size_line = p_end_line - buf + 1;
        break;
      }
    } else if (res == 0) {
      // fprintf(stderr, "[tid %u]connection closed\n", get_current_tid());
      exit_code = 1;
      break;
    } else {
      fprintf(stderr, "[tid %u]recv failed with error: %d\n", get_current_tid(),
              get_socket_error());
      exit_code = 3;
      break;
    }
  }

  return exit_code;
}
