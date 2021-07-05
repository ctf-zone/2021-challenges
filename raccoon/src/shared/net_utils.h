#ifndef NET_UTILS_H
#define NET_UTILS_H

#include "socket_cross.h"

#define DEFAULT_BUFLEN 16384

int get_port(const struct sockaddr *sa);
char *get_ip_str(const struct sockaddr *sa, char *s, socklen_t maxlen);
int send_all(SOCKET client_socket, const char *buf, size_t buflen);
int recv_msg(SOCKET client_socket, char *buf, size_t buflen, size_t *size_line,
             size_t *p_size_all_data);

#endif // NET_UTILS_H