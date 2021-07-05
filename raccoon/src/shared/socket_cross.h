#ifndef SOCKET_CROSS_H
#define SOCKET_CROSS_H

#include <stddef.h>
#if defined(WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define get_socket_error() (WSAGetLastError())
#pragma comment(lib, "Ws2_32.lib")
#else
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)

#define SD_RECEIVE SHUT_RD
#define SD_SEND SHUT_WR
#define SD_BOTH SHUT_RDWR

#define get_socket_error() (errno)
#define closesocket(x) close(x)
#endif

#endif // SOCKET_CROSS_H