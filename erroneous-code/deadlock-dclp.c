/*
 * test_deadlock_dclp.c
 *
 * Expected findings:
 *   - CWE-833:  Deadlock — inconsistent lock ordering (mtxA, mtxB)
 *   - CWE-609:  Double-Checked Locking Pattern (unsafe without barriers)
 *   - CWE-543:  Static local (singleton) without synchronisation
 *   - CWE-1058: Blocking call (sleep) in async callback
 *   - CWE-664:  Mutex lifecycle imbalance in error path
 *   - CWE-765:  Double unlock in error path
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

pthread_mutex_t mtxA = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mtxB = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;

/* Shared state for singleton */
int initialized = 0;
void *instance = NULL;

/* ---- CWE-833: Deadlock scenario ---- */

void *thread_func1(void *arg)
{
    /* Acquires mtxA then mtxB */
    pthread_mutex_lock(&mtxA);
    /* Simulate work */
    usleep(100);
    pthread_mutex_lock(&mtxB);

    printf("Thread 1 has both locks\n");

    pthread_mutex_unlock(&mtxB);
    pthread_mutex_unlock(&mtxA);
    return NULL;
}

void *thread_func2(void *arg)
{
    /* Acquires mtxB then mtxA — opposite order! */
    pthread_mutex_lock(&mtxB);
    usleep(100);
    pthread_mutex_lock(&mtxA);   /* Deadlock with thread_func1 */

    printf("Thread 2 has both locks\n");

    pthread_mutex_unlock(&mtxA);
    pthread_mutex_unlock(&mtxB);
    return NULL;
}

/* ---- CWE-609: Double-Checked Locking ---- */

void *get_instance(void)
{
    /* Classic broken DCLP — no memory barrier / atomic */
    if (!initialized) {
        pthread_mutex_lock(&init_lock);
        if (!initialized) {
            instance = malloc(1024);
            memset(instance, 0, 1024);
            initialized = 1;
        }
        pthread_mutex_unlock(&init_lock);
    }
    return instance;
}

/* ---- CWE-543: Singleton via static local without sync ---- */

void *thread_func3(void *arg)
{
    /* CWE-543: static local initialised without lock in thread context */
    static int first_call = 1;
    if (first_call) {
        first_call = 0;
        printf("Initialising from thread...\n");
    }

    get_instance();  /* Also triggers CWE-609 from above */

    return NULL;
}

/* ---- CWE-1058: Blocking in async-named callback ---- */

void async_on_event(int event_id)
{
    /* CWE-1058: sleep() is blocking, but this function name
       suggests it should be non-blocking */
    printf("Event %d received, processing...\n", event_id);
    sleep(5);  /* BUG: blocks the event loop */
}

/* ---- CWE-664 / CWE-765: Error path issues ---- */

int process_data(const char *data)
{
    pthread_mutex_lock(&mtxA);

    if (data == NULL) {
        /* CWE-664: early return without unlock — lock leaked */
        /* Also triggers CWE-765 if caller tries to unlock */
        pthread_mutex_unlock(&mtxA);
        pthread_mutex_unlock(&mtxA);  /* CWE-765: double unlock */
        return -1;
    }

    printf("Processing: %s\n", data);
    pthread_mutex_unlock(&mtxA);
    return 0;
}

int main(void)
{
    pthread_t t1, t2, t3a, t3b;

    /* CWE-572: return values not checked */
    pthread_create(&t1, NULL, thread_func1, NULL);
    pthread_create(&t2, NULL, thread_func2, NULL);
    pthread_create(&t3a, NULL, thread_func3, NULL);
    pthread_create(&t3b, NULL, thread_func3, NULL);

    async_on_event(42);

    process_data(NULL);
    process_data("hello");

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3a, NULL);
    pthread_join(t3b, NULL);

    return 0;
}
