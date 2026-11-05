/* Atlas rewrite benchmark: a small program written for Atlas (MIT, like the repository), mixing what real code
 * mixes: structs of mixed field sizes, a hash table, a bytecode interpreter with a large switch, recursion, callbacks
 * through function pointers, static helpers, variadic functions, double arithmetic, bit fields, global state and C
 * library calls. Built stripped by build.sh, with an unstripped copy as the answer key. */
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Global state and logging ---- */

struct stats {
  unsigned calls : 12;
  unsigned errors : 6;
  unsigned verbose : 1;
  unsigned level : 3;
  long bytes;
};

struct stats g_stats;
static char g_log[256];
static int g_log_len;

static void log_append(const char *s) {
  size_t n = strlen(s);
  if (g_log_len + n >= sizeof g_log) n = sizeof g_log - 1 - g_log_len;
  memcpy(g_log + g_log_len, s, n);
  g_log_len += (int)n;
  g_log[g_log_len] = 0;
}

int logf_(int level, const char *fmt, ...) {
  char buf[128];
  va_list ap;
  if (level > (int)g_stats.level) return 0;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  log_append(buf);
  g_stats.calls++;
  return n;
}

int sum_ints(int count, ...) {
  va_list ap;
  int total = 0;
  va_start(ap, count);
  for (int i = 0; i < count; i++) total += va_arg(ap, int);
  va_end(ap);
  return total;
}

/* ---- Strings ---- */

uint32_t hash_str(const char *s) {
  uint32_t h = 2166136261u;
  while (*s) {
    h ^= (unsigned char)*s++;
    h *= 16777619u;
  }
  return h;
}

int count_char(const char *s, char c) {
  int n = 0;
  for (; *s; s++) n += (*s == c);
  return n;
}

void reverse_in_place(char *s) {
  size_t n = strlen(s);
  for (size_t i = 0; i < n / 2; i++) {
    char t = s[i];
    s[i] = s[n - 1 - i];
    s[n - 1 - i] = t;
  }
}

int is_palindrome(const char *s) {
  size_t i = 0, j = strlen(s);
  while (j > i + 1) {
    if (s[i] != s[j - 1]) return 0;
    i++;
    j--;
  }
  return 1;
}

char *join_words(const char *const *words, int n, char sep) {
  size_t total = 1;
  for (int i = 0; i < n; i++) total += strlen(words[i]) + 1;
  char *out = malloc(total);
  if (out == NULL) return NULL;
  char *p = out;
  for (int i = 0; i < n; i++) {
    size_t len = strlen(words[i]);
    memcpy(p, words[i], len);
    p += len;
    if (i + 1 < n) *p++ = sep;
  }
  *p = 0;
  g_stats.bytes += (long)total;
  return out;
}

/* ---- Hash table ---- */

struct entry {
  char *key;
  int value;
  unsigned char used;
  struct entry *next;
};

struct table {
  struct entry **buckets;
  unsigned size;
  unsigned count;
};

struct table *table_new(unsigned size) {
  struct table *t = calloc(1, sizeof *t);
  if (t == NULL) return NULL;
  t->buckets = calloc(size, sizeof *t->buckets);
  if (t->buckets == NULL) {
    free(t);
    return NULL;
  }
  t->size = size;
  return t;
}

static struct entry *table_find(const struct table *t, const char *key, uint32_t h) {
  for (struct entry *e = t->buckets[h % t->size]; e != NULL; e = e->next)
    if (strcmp(e->key, key) == 0) return e;
  return NULL;
}

int table_put(struct table *t, const char *key, int value) {
  uint32_t h = hash_str(key);
  struct entry *e = table_find(t, key, h);
  if (e != NULL) {
    e->value = value;
    return 0;
  }
  e = malloc(sizeof *e);
  if (e == NULL) return -1;
  e->key = strdup(key);
  e->value = value;
  e->used = 1;
  e->next = t->buckets[h % t->size];
  t->buckets[h % t->size] = e;
  t->count++;
  return 1;
}

int table_get(const struct table *t, const char *key, int fallback) {
  struct entry *e = table_find(t, key, hash_str(key));
  return e != NULL ? e->value : fallback;
}

void table_free(struct table *t) {
  for (unsigned i = 0; i < t->size; i++) {
    struct entry *e = t->buckets[i];
    while (e != NULL) {
      struct entry *next = e->next;
      free(e->key);
      free(e);
      e = next;
    }
  }
  free(t->buckets);
  free(t);
}

/* ---- Numbers ---- */

double mean(const double *v, int n) {
  double s = 0;
  for (int i = 0; i < n; i++) s += v[i];
  return n > 0 ? s / n : 0.0;
}

double stddev(const double *v, int n) {
  double m = mean(v, n), s = 0;
  for (int i = 0; i < n; i++) s += (v[i] - m) * (v[i] - m);
  return n > 1 ? sqrt(s / (n - 1)) : 0.0;
}

long fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

long gcd(long a, long b) {
  while (b != 0) {
    long t = a % b;
    a = b;
    b = t;
  }
  return a < 0 ? -a : a;
}

int popcount32(uint32_t x) {
  x = x - ((x >> 1) & 0x55555555u);
  x = (x & 0x33333333u) + ((x >> 2) & 0x33333333u);
  return (int)((((x + (x >> 4)) & 0x0f0f0f0fu) * 0x01010101u) >> 24);
}

int clamp(int v, int lo, int hi) { return v < lo ? lo : v > hi ? hi : v; }

/* ---- Sorting with callbacks ---- */

struct item {
  short id;
  char tag;
  int weight;
  double score;
};

static int by_weight(const void *a, const void *b) {
  const struct item *x = a, *y = b;
  return (x->weight > y->weight) - (x->weight < y->weight);
}

static int by_score_desc(const void *a, const void *b) {
  const struct item *x = a, *y = b;
  return (x->score < y->score) - (x->score > y->score);
}

void sort_items(struct item *items, size_t n, int mode) {
  qsort(items, n, sizeof *items, mode == 0 ? by_weight : by_score_desc);
}

int apply_all(int *v, int n, int (*f)(int, void *), void *ctx) {
  int changed = 0;
  for (int i = 0; i < n; i++) {
    int r = f(v[i], ctx);
    changed += (r != v[i]);
    v[i] = r;
  }
  return changed;
}

static int add_ctx(int x, void *ctx) { return x + *(int *)ctx; }

int add_to_all(int *v, int n, int k) { return apply_all(v, n, add_ctx, &k); }

/* ---- A small stack machine ---- */

enum op { OP_PUSH, OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_DUP, OP_SWAP, OP_JZ, OP_JMP, OP_PRINT, OP_HALT };

struct insn {
  unsigned char op;
  int arg;
};

struct vm {
  long stack[64];
  int sp;
  int pc;
  int steps;
};

static long vm_pop(struct vm *m) { return m->sp > 0 ? m->stack[--m->sp] : 0; }

static void vm_push(struct vm *m, long v) {
  if (m->sp < 64) m->stack[m->sp++] = v;
  else g_stats.errors++;
}

long vm_run(struct vm *m, const struct insn *code, int len) {
  long a, b;
  while (m->pc < len && m->steps++ < 10000) {
    const struct insn *i = &code[m->pc++];
    switch (i->op) {
    case OP_PUSH: vm_push(m, i->arg); break;
    case OP_ADD: b = vm_pop(m); a = vm_pop(m); vm_push(m, a + b); break;
    case OP_SUB: b = vm_pop(m); a = vm_pop(m); vm_push(m, a - b); break;
    case OP_MUL: b = vm_pop(m); a = vm_pop(m); vm_push(m, a * b); break;
    case OP_DIV:
      b = vm_pop(m);
      a = vm_pop(m);
      if (b == 0) {
        g_stats.errors++;
        return -1;
      }
      vm_push(m, a / b);
      break;
    case OP_DUP: a = vm_pop(m); vm_push(m, a); vm_push(m, a); break;
    case OP_SWAP: b = vm_pop(m); a = vm_pop(m); vm_push(m, b); vm_push(m, a); break;
    case OP_JZ: if (vm_pop(m) == 0) m->pc = i->arg; break;
    case OP_JMP: m->pc = i->arg; break;
    case OP_PRINT: logf_(1, "%ld\n", m->sp > 0 ? m->stack[m->sp - 1] : 0L); break;
    case OP_HALT: return m->sp > 0 ? m->stack[m->sp - 1] : 0;
    default: g_stats.errors++; return -2;
    }
  }
  return m->sp > 0 ? m->stack[m->sp - 1] : 0;
}

/* ---- Trees ---- */

struct node {
  int key;
  struct node *left, *right;
};

struct node *tree_insert(struct node *root, int key) {
  if (root == NULL) {
    struct node *n = calloc(1, sizeof *n);
    if (n != NULL) n->key = key;
    return n;
  }
  if (key < root->key) root->left = tree_insert(root->left, key);
  else if (key > root->key) root->right = tree_insert(root->right, key);
  return root;
}

int tree_height(const struct node *n) {
  if (n == NULL) return 0;
  int l = tree_height(n->left), r = tree_height(n->right);
  return 1 + (l > r ? l : r);
}

void tree_free(struct node *n) {
  if (n == NULL) return;
  tree_free(n->left);
  tree_free(n->right);
  free(n);
}

/* ---- Main ---- */

int main(int argc, char **argv) {
  static const struct insn program[] = {{OP_PUSH, 6}, {OP_PUSH, 7}, {OP_MUL, 0}, {OP_PRINT, 0}, {OP_HALT, 0}};
  struct vm m = {0};
  g_stats.level = 2;
  struct table *t = table_new(31);
  for (int i = 1; i < argc; i++) table_put(t, argv[i], i);
  printf("%ld %ld %d %d\n", vm_run(&m, program, 5), fib(10), table_get(t, "x", -1), popcount32(0xf0f0u));
  table_free(t);
  return 0;
}
