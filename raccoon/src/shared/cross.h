#ifndef CROSS_H
#define CROSS_H

#if !defined(_MSC_VER)
#define UNREFERENCED_PARAMETER(x) (void)x

typedef int errno_t;
errno_t fopen_s(FILE **fp, const char *filename, const char *mode);
errno_t strcpy_s(char *dst, size_t sizeof_dst, const char *src);
errno_t strcat_s(char *dst, size_t sizeof_dst, const char *src);
errno_t memcpy_s(void *dst, size_t sizeof_dst, const void *src, size_t count);
errno_t memmove_s(void *dst, size_t sizeof_dst, const void *src, size_t count);
size_t strnlen_s(const char *src, size_t dmax);
#define sprintf_s snprintf

#define max(a, b)                                                              \
  ({                                                                           \
    typeof(a) _a = (a);                                                        \
    typeof(b) _b = (b);                                                        \
    _a > _b ? _a : _b;                                                         \
  })
#define min(a, b)                                                              \
  ({                                                                           \
    typeof(a) _a = (a);                                                        \
    typeof(b) _b = (b);                                                        \
    _a < _b ? _a : _b;                                                         \
  })

#endif

#endif // CROSS_H