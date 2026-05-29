#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include "../include/threadpool.h"

static void *worker(void *arg) {
    ThreadPool *pool = (ThreadPool *)arg;

    while (1) {
        pthread_mutex_lock(&pool->lock);

        while (pool->queue_size == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->notify, &pool->lock);
        }

        if (pool->shutdown && pool->queue_size == 0) {
            pthread_mutex_unlock(&pool->lock);
            break;
        }

        Task *task = pool->queue_head;
        pool->queue_head = task->next;
        if (pool->queue_head == NULL)
            pool->queue_tail = NULL;
        pool->queue_size--;

        pthread_mutex_unlock(&pool->lock);

        // executam task-ul
        scan_port(task->ip, task->port, task->timeout_ms);
        
        struct timeval t1, t2;
        gettimeofday(&t1, NULL);
        int is_open = scan_port(task->ip, task->port, task->timeout_ms);
        gettimeofday(&t2, NULL);

        double elapsed = (t2.tv_sec - t1.tv_sec) * 1000.0 +
                         (t2.tv_usec - t1.tv_usec) / 1000.0;

        task->result->port = task->port;
        task->result->open = is_open;
        task->result->response_time_ms = elapsed;
        strncpy(task->result->service, get_service_name(task->port), 31);
        task->result->banner[0] = '\0';

        if (is_open) {
            grab_banner(task->ip, task->port, task->timeout_ms,
                        task->result->banner, sizeof(task->result->banner));
            printf("  [+] Port %-6d %-12s %.1f ms\n",
                   task->port, task->result->service, elapsed);
            fflush(stdout);
        }

        free(task);

        pthread_mutex_lock(&pool->lock);
        pool->completed++;
        pthread_mutex_unlock(&pool->lock);
    }

    return NULL;
}

ThreadPool* threadpool_create(int thread_count) {
    ThreadPool *pool = malloc(sizeof(ThreadPool));
    memset(pool, 0, sizeof(ThreadPool));

    pool->thread_count = thread_count;
    pool->threads = malloc(sizeof(pthread_t) * thread_count);
    pool->shutdown = 0;
    pool->completed = 0;
    pool->queue_head = NULL;
    pool->queue_tail = NULL;
    pool->queue_size = 0;

    pthread_mutex_init(&pool->lock, NULL);
    pthread_cond_init(&pool->notify, NULL);

    for (int i = 0; i < thread_count; i++) {
        pthread_create(&pool->threads[i], NULL, worker, pool);
    }

    return pool;
}

void threadpool_add(ThreadPool *pool, const char *ip, int port, int timeout_ms, PortResult *result) {
    Task *task = malloc(sizeof(Task));
    task->ip = ip;
    task->port = port;
    task->timeout_ms = timeout_ms;
    task->result = result;
    task->next = NULL;

    pthread_mutex_lock(&pool->lock);

    if (pool->queue_tail == NULL) {
        pool->queue_head = task;
        pool->queue_tail = task;
    } else {
        pool->queue_tail->next = task;
        pool->queue_tail = task;
    }
    pool->queue_size++;
    pool->total++;

    pthread_cond_signal(&pool->notify);
    pthread_mutex_unlock(&pool->lock);
}

void threadpool_wait(ThreadPool *pool) {
    pthread_mutex_lock(&pool->lock);
    while (pool->completed < pool->total) {
        pthread_mutex_unlock(&pool->lock);
        usleep(10000); // 10ms
        pthread_mutex_lock(&pool->lock);
    }
    pthread_mutex_unlock(&pool->lock);
}

void threadpool_destroy(ThreadPool *pool) {
    pthread_mutex_lock(&pool->lock);
    pool->shutdown = 1;
    pthread_cond_broadcast(&pool->notify);
    pthread_mutex_unlock(&pool->lock);

    for (int i = 0; i < pool->thread_count; i++) {
        pthread_join(pool->threads[i], NULL);
    }

    pthread_mutex_destroy(&pool->lock);
    pthread_cond_destroy(&pool->notify);
    free(pool->threads);
    free(pool);
}
