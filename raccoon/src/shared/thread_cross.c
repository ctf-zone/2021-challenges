#if defined(WIN32)
#include <Windows.h>
#include <process.h>
#endif
#if defined(__GNUC__)
#define _GNU_SOURCE
#include <unistd.h>
#include <pthread.h>
#endif

#include "thread_cross.h"

int begin_thread(pthread_t *thread, THREADFUNC worker_thread,
                 void *worker_data) {
#if defined(WIN32)
  *thread = _beginthread(worker_thread, 0, worker_data);
  if (*thread == -1) {
    return errno;
  }
  return 0;
#else
  typedef void *(*PTHREADFUNC)(void *);
  int res;
  res = pthread_create(thread, NULL, (PTHREADFUNC)worker_thread, worker_data);
  return res;
#endif
}

int detach_thread(pthread_t thread) {
#if defined(WIN32)
  BOOL is_success = CloseHandle((HANDLE)thread);
  if (is_success == 0) {
    return GetLastError();
  }
  return 0;
#else
  return pthread_detach(thread);
#endif
}

void exit_thread() {
#if defined(WIN32)
  _endthread();
#else
  pthread_exit(NULL);
#endif
}

pid_t get_current_tid() {
  pid_t tid;
#if defined(WIN32)
  tid = (pid_t)GetCurrentThreadId();
#else
  tid = gettid();
#endif
  return tid;
}
