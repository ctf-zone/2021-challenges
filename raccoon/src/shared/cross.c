#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "cross.h"

#if !defined(WIN32)
errno_t fopen_s(FILE **pp_file, const char *file_name, const char *mode) {
  if (pp_file == NULL || file_name == NULL || mode == NULL) {
    return EINVAL;
  }
  *pp_file = fopen(file_name, mode);
  if (*pp_file != NULL) {
    return 0;
  }

  return errno;
}

errno_t strcpy_s(char *dst, size_t sizeof_dst, const char *src) {
  size_t i;

  if (sizeof_dst == 0) {
    return ERANGE;
  }

  if (dst == NULL) {
    return EINVAL;
  }

  if (src == NULL) {
    dst[0] = 0;
    return EINVAL;
  }

  for (i = 0; src[i]; i++) {
    if (i >= sizeof_dst) {
      dst[0] = 0;
      return ERANGE;
    } else {
      dst[i] = src[i];
    }
  }
  if (i >= sizeof_dst) {
    dst[0] = 0;
    return ERANGE;
  } else {
    dst[i] = src[i];
  }

  return 0;
}

errno_t strcat_s(char *dst, size_t sizeof_dst, const char *src) {
  char *p_dst;
  const char *p_src;
  size_t buffer_left = sizeof_dst;

  if (!dst || !src) {
    if (dst) {
      *dst = 0;
    }
    return EINVAL;
  }

  if (buffer_left == 0) {
    *dst = 0;
    return ERANGE;
  }

  p_dst = dst;
  p_src = src;
  while (*p_dst) {
    p_dst++;
    buffer_left--;
  }

  if (buffer_left == 0) {
    *dst = 0;
    return ERANGE;
  }

  while ((*p_dst++ = *p_src++) != 0 && --buffer_left > 0)
    ;

  if (buffer_left == 0) {
    *dst = 0;
    return ERANGE;
  }

  return 0;
}

errno_t memcpy_s(void *dst, size_t sizeof_dst, const void *src, size_t count) {

  if (count == 0) {
    return 0;
  }

  if (dst == NULL) {
    return EINVAL;
  }

  if (src == NULL || sizeof_dst < count) {
    memset(dst, 0, sizeof_dst);
    if (src == NULL) {
      return EINVAL;
    }
    return ERANGE;
  }

  memcpy(dst, src, count);
  return 0;
}

errno_t memmove_s(void *dst, size_t sizeof_dst, const void *src, size_t count) {
  void *p_ret = NULL;

  if (count == 0) {
    return 0;
  }
  if (dst == NULL) {
    return EINVAL;
  }
  if (src == NULL) {
    return EINVAL;
  }
  if (sizeof_dst < count) {
    return ERANGE;
  }

  p_ret = memmove(dst, src, count);
  return p_ret != NULL ? 0 : ENOMEM;
}

size_t strnlen_s(const char *src, size_t dmax) {

  size_t count = 0;

  if (src == NULL || dmax == 0) {
    return 0;
  }

  while (*src && dmax) {
    count++;
    dmax--;
    src++;
  }

  return count;
}

#endif