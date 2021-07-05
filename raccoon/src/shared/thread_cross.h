#ifndef THREAD_CROSS_H
#define THREAD_CROSS_H

#if defined(WIN32)
typedef unsigned int pid_t;
typedef uintptr_t pthread_t;
#endif

typedef void (*THREADFUNC)(void *);

int begin_thread(pthread_t *thread, THREADFUNC worker_thread,
                 void *worker_data);
int detach_thread(pthread_t thread);
void exit_thread();
pid_t get_current_tid();

#endif // THREAD_CROSS_H
