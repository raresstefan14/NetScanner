#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <pthread.h>
#include "scanner.h"

typedef struct Task {
    const char *ip;
    int port;
    int timeout_ms;
    PortResult *result;
    struct Task *next;
} Task;

typedef struct {
    pthread_t *threads;
    int thread_count;

    Task *queue_head;
    Task *queue_tail;
    int queue_size;

    pthread_mutex_t lock;
    pthread_cond_t notify;

    int shutdown;
    int completed;
    int total;
} ThreadPool;

ThreadPool* threadpool_create(int thread_count);
void threadpool_add(ThreadPool *pool, const char *ip, int port, int timeout_ms, PortResult *result);
void threadpool_wait(ThreadPool *pool);
void threadpool_destroy(ThreadPool *pool);

#endif
