/*
 * test_race_and_locking.c
 *
 * Expected:
 *   CWE-362/567  counter accessed without lock in worker
 *   CWE-764      double lock on mtx
 *   CWE-832      unlock of mtx2 never locked
 *   CWE-667      worker exits with mtx still held
 *   CWE-572      pthread_create return unchecked
 *   CWE-663      strtok (non-reentrant) in thread
 *   CWE-585      empty critical section on mtx2
 *   CWE-664      lock/unlock count mismatch on mtx
 */

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int counter = 0;
int flag = 0;

pthread_mutex_t mtx  = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mtx2 = PTHREAD_MUTEX_INITIALIZER;

void *worker(void *arg)
{
    /* CWE-362/567: unprotected shared access */
    int local = counter;
    local++;
    counter = local;

    /* CWE-764: double lock */
    pthread_mutex_lock(&mtx);
    pthread_mutex_lock(&mtx);

    flag = 1;

    pthread_mutex_unlock(&mtx);
    /* CWE-667: mtx still held (locked 2x, unlocked 1x) */

    /* CWE-832: mtx2 never locked in this function */
    pthread_mutex_unlock(&mtx2);

    /* CWE-663: strtok is non-reentrant */
    char buf[] = "a,b,c";
    char *tok = strtok(buf, ",");
    while (tok) {
        printf("%s\n", tok);
        tok = strtok(NULL, ",");
    }

    /* CWE-585: empty critical section */
    pthread_mutex_lock(&mtx2);
    pthread_mutex_unlock(&mtx2);

    return NULL;
}

int main(void)
{
    pthread_t t1, t2;

    /* CWE-572: return value