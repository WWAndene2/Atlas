/* The console kernel's threads (after console/kernel.inc): guest threads, their scheduling, and what they wait on
 * (events, mutexes, semaphores, threads, addresses, time). No console in it: a profile maps its system calls here.
 *
 * Each guest thread is a host thread with its own guest state (the translations take the state as an argument, and
 * share the guest memory), but only one runs guest code at a time: it holds console_lock, and hands it over by
 * scheduling. A thread runs until it blocks, yields, or makes a higher-priority thread ready (a lower number runs
 * first; equal priorities take turns): a console's application core, deterministic run to run, without a host
 * scheduler's choices in the guest's results. A thread interrupted between system calls (preemption by a timer)
 * is not modelled: a program that spins on memory another thread writes, without a system call, never yields. */
#include <pthread.h>
#include <time.h>

#define CONSOLE_THREADS 64
#define CONSOLE_WAIT_HANDLES 64
#define CONSOLE_FOREVER UINT64_MAX
enum console_thread_state { CONSOLE_THREAD_FREE, CONSOLE_THREAD_READY, CONSOLE_THREAD_WAITING, CONSOLE_THREAD_DEAD };
enum console_wait { CONSOLE_WAIT_SLEEP, CONSOLE_WAIT_OBJECTS, CONSOLE_WAIT_ADDRESS };

struct console_thread {
  enum console_thread_state state;
  int priority;
  atlas_state *s;
  uint64_t entry;
  pthread_cond_t turn;
  /* While waiting: what for, until when (monotonic nanoseconds), and, once it is over, how it ended. */
  enum console_wait wait;
  uint64_t deadline;
  uint32_t handles[CONSOLE_WAIT_HANDLES];
  int count, all;
  uint32_t address;
  int woken, index, timed_out;
};
static struct console_thread console_threads[CONSOLE_THREADS];
static pthread_mutex_t console_lock = PTHREAD_MUTEX_INITIALIZER;
static int console_current;        /* the thread allowed to run guest code */
static __thread int console_self;  /* this host thread's guest thread */

static uint64_t console_now(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

/* A deadline from a relative timeout in nanoseconds; a negative one waits for ever. */
static uint64_t console_deadline(int64_t timeout) {
  return timeout < 0 ? CONSOLE_FOREVER : console_now() + (uint64_t)timeout;
}

/* ---- Objects a thread can wait on. An event: count is whether it is signalled, limit its reset (0: one waiter
 * clears it, as for a pulse; 1: it stays signalled until cleared). A mutex: value is its owner + 1 (0: free), count
 * how many times the owner holds it. A semaphore: count, limit its maximum. A thread: value its index, signalled
 * once it ended. */
static int console_signalled(struct console_object *o, int thread) {
  switch (o->kind) {
    case CONSOLE_EVENT: return o->count != 0;
    case CONSOLE_MUTEX: return o->value == 0 || o->value == (uint64_t)thread + 1;
    case CONSOLE_SEMAPHORE: return o->count > 0;
    case CONSOLE_THREAD: return console_threads[o->value].state == CONSOLE_THREAD_DEAD;
    default: return 0;
  }
}

static void console_acquire(struct console_object *o, int thread) {
  if (o->kind == CONSOLE_EVENT && o->limit == 0) o->count = 0;
  if (o->kind == CONSOLE_MUTEX) {
    o->value = (uint64_t)thread + 1;
    o->count++;
  }
  if (o->kind == CONSOLE_SEMAPHORE) o->count--;
}

/* Whether a wait on objects is over now: the index of the object that ended it (or 0 when all were waited for and
 * all are signalled), else -1. Nothing is acquired. */
static int console_objects_ready(struct console_thread *t, int thread) {
  int signalled = 0, first = -1;
  for (int k = 0; k < t->count; k++) {
    struct console_object *o = console_handle_get(t->handles[k]);
    if (o != NULL && console_signalled(o, thread)) {
      signalled++;
      if (first < 0) first = k;
    }
  }
  if (t->all) return signalled == t->count ? 0 : -1;
  return first;
}

static void console_objects_acquire(struct console_thread *t, int thread, int index) {
  for (int k = 0; k < t->count; k++)
    if (t->all || k == index) console_acquire(console_handle_get(t->handles[k]), thread);
}

static int console_runnable(int k, uint64_t now) {
  struct console_thread *t = &console_threads[k];
  if (t->state == CONSOLE_THREAD_READY) return 1;
  if (t->state != CONSOLE_THREAD_WAITING) return 0;
  if (now >= t->deadline) return 1;
  if (t->wait == CONSOLE_WAIT_OBJECTS) return console_objects_ready(t, k) >= 0;
  if (t->wait == CONSOLE_WAIT_ADDRESS) return t->woken;
  return 0;
}

/* Ends a runnable thread's wait: what it waited for is acquired, or it timed out. */
static void console_wake(int k, uint64_t now) {
  struct console_thread *t = &console_threads[k];
  if (t->state != CONSOLE_THREAD_WAITING) return;
  t->timed_out = 0;
  if (t->wait == CONSOLE_WAIT_OBJECTS) {
    t->index = console_objects_ready(t, k);
    if (t->index >= 0) console_objects_acquire(t, k, t->index);
    else t->timed_out = 1;
  } else if (t->wait == CONSOLE_WAIT_ADDRESS) {
    t->timed_out = !t->woken;
  }
  (void)now;
  t->state = CONSOLE_THREAD_READY;
}

/* Lets the highest-priority runnable thread run, this one included unless it yields (then it goes after the others
 * of its priority). Returns when this thread runs again, or at once if it ended. With nothing runnable, it waits for
 * the nearest deadline; with no deadline either, every thread waits for ever, and the program stops saying so. */
static void console_schedule(int yield) {
  int me = console_self;
  for (;;) {
    uint64_t now = console_now(), nearest = CONSOLE_FOREVER;
    int best = -1;
    for (int k = 1; k <= CONSOLE_THREADS; k++) {
      int i = (me + k) % CONSOLE_THREADS; /* this thread last: among equals, the next one goes first */
      if (!console_runnable(i, now)) {
        if (console_threads[i].state == CONSOLE_THREAD_WAITING && console_threads[i].deadline < nearest)
          nearest = console_threads[i].deadline;
        continue;
      }
      if (best < 0 || console_threads[i].priority < console_threads[best].priority) best = i;
    }
    if (!yield && console_runnable(me, now) && (best < 0 || console_threads[me].priority <= console_threads[best].priority))
      best = me;
    if (best >= 0) {
      console_wake(best, now);
      if (best == me) return;
      console_current = best;
      pthread_cond_signal(&console_threads[best].turn);
      if (console_threads[me].state == CONSOLE_THREAD_DEAD) return;
      while (console_current != me) pthread_cond_wait(&console_threads[me].turn, &console_lock);
      return;
    }
    if (nearest == CONSOLE_FOREVER) {
      fprintf(stderr, "atlas: every guest thread waits for ever\n");
      exit(1);
    }
    struct timespec pause = {(time_t)((nearest - now) / 1000000000u), (long)((nearest - now) % 1000000000u)};
    nanosleep(&pause, NULL);
  }
}

/* ---- Waits, as a profile's system calls make them. Each returns once the wait is over. */

/* Waits on objects (any one, or all): the index of the one that ended the wait (0 for all), -1 on timeout, -2 for
 * a handle that names no object. A wait already satisfied returns at once, without scheduling. */
static int console_wait_objects(const uint32_t *handles, int count, int all, int64_t timeout) {
  struct console_thread *t = &console_threads[console_self];
  if (count < 0 || count > CONSOLE_WAIT_HANDLES) return -2;
  for (int k = 0; k < count; k++)
    if (console_handle_get(handles[k]) == NULL) return -2;
  memcpy(t->handles, handles, (size_t)count * sizeof handles[0]);
  t->count = count;
  t->all = all;
  t->wait = CONSOLE_WAIT_OBJECTS;
  int index = console_objects_ready(t, console_self);
  if (index >= 0) {
    console_objects_acquire(t, console_self, index);
    return index;
  }
  if (timeout == 0) return -1;
  t->deadline = console_deadline(timeout);
  t->state = CONSOLE_THREAD_WAITING;
  console_schedule(1);
  return t->timed_out ? -1 : t->index;
}

static void console_sleep(int64_t timeout) {
  struct console_thread *t = &console_threads[console_self];
  if (timeout > 0) {
    t->wait = CONSOLE_WAIT_SLEEP;
    t->deadline = console_deadline(timeout);
    t->state = CONSOLE_THREAD_WAITING;
  }
  console_schedule(1);
}

/* Waits until another thread signals the guest address (an address arbiter, a futex): 0, or -1 on timeout. */
static int console_wait_address(uint32_t address, int64_t timeout) {
  struct console_thread *t = &console_threads[console_self];
  t->wait = CONSOLE_WAIT_ADDRESS;
  t->address = address;
  t->woken = 0;
  t->deadline = console_deadline(timeout);
  t->state = CONSOLE_THREAD_WAITING;
  console_schedule(1);
  return t->timed_out ? -1 : 0;
}

/* Wakes up to count threads waiting on the address (all for a negative count), highest priority first. */
static void console_signal_address(uint32_t address, int count) {
  for (int n = 0; count < 0 || n < count; n++) {
    int best = -1;
    for (int k = 0; k < CONSOLE_THREADS; k++) {
      struct console_thread *t = &console_threads[k];
      if (t->state == CONSOLE_THREAD_WAITING && t->wait == CONSOLE_WAIT_ADDRESS && t->address == address &&
          !t->woken && (best < 0 || t->priority < console_threads[best].priority))
        best = k;
    }
    if (best < 0) return;
    console_threads[best].woken = 1;
  }
}

/* ---- Threads' lives. */

/* The calling host thread becomes guest thread 0, running (with the state the program starts in). */
static void console_threads_start(atlas_state *s, int priority) {
  pthread_mutex_lock(&console_lock);
  console_threads[0].state = CONSOLE_THREAD_READY;
  console_threads[0].priority = priority;
  console_threads[0].s = s;
  pthread_cond_init(&console_threads[0].turn, NULL);
  console_self = console_current = 0;
}

static void console_thread_exit(void) {
  console_threads[console_self].state = CONSOLE_THREAD_DEAD;
  console_schedule(1);
  pthread_mutex_unlock(&console_lock);
  pthread_exit(NULL);
}

static void *console_thread_main(void *argument) {
  int k = (int)(intptr_t)argument;
  pthread_mutex_lock(&console_lock);
  console_self = k;
  while (console_current != k) pthread_cond_wait(&console_threads[k].turn, &console_lock);
  atlas_call(console_threads[k].s, console_threads[k].entry);
  console_thread_exit(); /* a thread whose entry returns ends, as if it had asked to */
  return NULL;
}

/* A new thread, ready to run at entry, its guest state a copy of the creator's (the profile then sets its
 * arguments, stack and thread storage, before console_thread_go). Its index, or -1 when there is no room. */
static int console_thread_new(int priority, uint64_t entry) {
  for (int k = 1; k < CONSOLE_THREADS; k++) {
    struct console_thread *t = &console_threads[k];
    if (t->state != CONSOLE_THREAD_FREE) continue;
    atlas_state *s = malloc(sizeof *s);
    if (s == NULL) return -1;
    *s = *console_threads[console_self].s;
    s->returned = 0;
    *t = (struct console_thread){.priority = priority, .s = s, .entry = entry};
    pthread_cond_init(&t->turn, NULL);
    return k;
  }
  return -1;
}

/* Starts the new thread's host thread; it runs once scheduled (at once if its priority is higher). */
static int console_thread_go(int k) {
  pthread_t host;
  pthread_attr_t attributes;
  pthread_attr_init(&attributes);
  pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize(&attributes, 64u << 20); /* translated code keeps deep host frames */
  if (pthread_create(&host, &attributes, console_thread_main, (void *)(intptr_t)k) != 0) return 0;
  console_threads[k].state = CONSOLE_THREAD_READY;
  console_schedule(0);
  return 1;
}
