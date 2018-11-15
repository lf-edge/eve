/*
Copyright (c) 2009 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

typedef void (threadpool_func_t)(void*);

typedef struct threadpool threadpool_t;

/* Create a new thread pool.  The wake up callback will be called often
   enough to make sure that the caller can flush the callback queue. */
threadpool_t *threadpool_create(int maxthreads,
                                threadpool_func_t *wakeup,
                                void *wakeup_closure);

/* Cause a thread pool to die.  Returns whenever there is new stuff in the
   callback queue, or immediately if canblock is false.  Returns true when
   the thread pool is dead. */
int threadpool_die(threadpool_t *threadpool, int canblock);

/* Destroy a thread pool.  Does nothing and returns -1 if the pool is not
   dead. */
int threadpool_destroy(threadpool_t *threadpool);

/* Schedule a new piece of work for a thread pool.  Returns -1 if something
   went wrong. */
int threadpool_schedule(threadpool_t *threadpool,
                         threadpool_func_t *func, void *closure);

/* Schedule a callback for the main loop.  This may be called by any
   thread, not only one that belongs to the thread pool. */
int threadpool_schedule_back(threadpool_t *threadpool,
                              threadpool_func_t *func, void *closure);

/* Execute all queued callbacks.  This should be called in a timely
   manner after the wakeup function has been called.  Calling it more
   often than that doesn't harm, the nothing-to-do case is extremely
   fast and doesn't take any locks. */
void threadpool_run_callbacks(threadpool_t *threadpool);
