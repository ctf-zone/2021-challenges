#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdio.h>
#include <stdbool.h>

#define REGRESS_1(x)                                                           \
  if (!(x)) {                                                                  \
    return (printf("Regression failed %s:%d.\n", __FILE__, __LINE__) | 1);     \
  }
#define REGRESS_2(x, str_fmt)                                                  \
  if (!(x)) {                                                                  \
    return (                                                                   \
        printf("Regression failed %s:%d. " str_fmt "\n", __FILE__, __LINE__) | \
        1);                                                                    \
  }
#define REGRESS_3(x, str_fmt, ...)                                             \
  if (!(x)) {                                                                  \
    return (printf("Regression failed %s:%d. " str_fmt "\n", __FILE__,         \
                   __LINE__, __VA_ARGS__) |                                    \
            1);                                                                \
  }
#define REGRESS_NOT_RET_1(x)                                                   \
  if (!(x)) {                                                                  \
    printf("Regression failed %s:%d.\n", __FILE__, __LINE__);                  \
  }
#define REGRESS_NOT_RET_2(x, str_fmt)                                          \
  if (!(x)) {                                                                  \
    printf("Regression failed %s:%d. " str_fmt "\n", __FILE__, __LINE__);      \
  }
#define REGRESS_NOT_RET_3(x, str_fmt, ...)                                     \
  if (!(x)) {                                                                  \
    printf("Regression failed %s:%d. " str_fmt "\n", __FILE__, __LINE__,       \
           __VA_ARGS__);                                                       \
  }
#define REGRESS_ERROR() REGRESS_1(false)

#endif // TEST_UTILS_H