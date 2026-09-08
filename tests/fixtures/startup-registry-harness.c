/* Minimal host substitutes for GLib and FILE operations. The functions under
 * test are extracted from upstream libc-shim.c, then patched by the builder. */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define TRUE 1
#define FALSE 0
#define HAVE_FRIDA_DIR
#define FRIDA_STDIO_OPAQUE_FILE
#define G_LOCK(name) assert(pthread_mutex_lock(&mutex) == 0)
#define G_UNLOCK(name) assert(pthread_mutex_unlock(&mutex) == 0)
typedef void *gpointer;
typedef struct { int flushed; } FridaFile;
typedef struct { FridaFile *impl; } FridaFileHandle;
typedef struct { int unused; } DIR;
typedef struct { void *items[32]; int n; } GHashTable;
typedef struct { GHashTable *table; int index; } GHashTableIter;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static GHashTable *frida_streams, *frida_dirs;
static GHashTable *early_streams, *early_dirs;
static int frida_libc_shim_initialized, allocations, gum_calls;
static int g_direct_hash, g_direct_equal;
static FridaFileHandle frida_stdio[3];
static FridaFile early_file, closed_file;
static DIR early_dir, closed_dir;
static void frida_stdio_register_stream(FILE *);
static void frida_stdio_unregister_stream(FILE *);
static void frida_stdio_register_dir(DIR *);
static void frida_stdio_unregister_dir(DIR *);
static void frida_flush_all_streams(int *);
static GHashTable *g_hash_table_new(int hash, int equal) {
  (void) hash; (void) equal; allocations++;
  return calloc(1, sizeof(GHashTable));
}
static void g_hash_table_add(GHashTable *table, void *item) {
  assert(table != NULL && "registration needs an initialized registry");
  assert(table->n < 32); table->items[table->n++] = item;
}
static void g_hash_table_remove(GHashTable *table, void *item) {
  assert(table != NULL);
  for (int i = 0; i < table->n; i++) if (table->items[i] == item) {
    table->items[i] = table->items[--table->n]; return;
  }
  assert(0 && "registered object was lost");
}
static void g_hash_table_iter_init(GHashTableIter *iter, GHashTable *table) {
  assert(table != NULL); iter->table = table; iter->index = 0;
}
static int g_hash_table_iter_next(GHashTableIter *iter, void **key, void *value) {
  (void) value;
  if (iter->index == iter->table->n) return 0;
  *key = iter->table->items[iter->index++]; return 1;
}
static FridaFile *frida_file_get_impl(FILE *file) { return (FridaFile *) file; }
static int frida_file_flush_write(FridaFile *file) { file->flushed++; return 0; }
static FridaFile *frida_file_new(int fd, int close_fd, int mode) {
  (void) fd; (void) close_fd; (void) mode; return calloc(1, sizeof(FridaFile));
}
static void frida_file_bind_slot(FILE *slot, FridaFile *file) {
  ((FridaFileHandle *) slot)->impl = file;
}
static void gum_init_embedded(void) {
  gum_calls++;
  assert(!frida_libc_shim_initialized);
  frida_stdio_register_stream((FILE *) &early_file);
  frida_stdio_register_stream((FILE *) &closed_file);
  frida_stdio_unregister_stream((FILE *) &closed_file);
  frida_stdio_register_dir(&early_dir);
  frida_stdio_register_dir(&closed_dir);
  frida_stdio_unregister_dir(&closed_dir);
  early_streams = frida_streams;
  early_dirs = frida_dirs;
}

/* UPSTREAM_FUNCTIONS */

static void *register_concurrently(void *item) {
  frida_stdio_register_stream((FILE *) item);
  return NULL;
}
int main(int argc, char **argv) {
  (void) argv;
  int result = 0;
  if (argc > 1) {
    /* The unpatched source fails here, on the first open during Gum init. */
    frida_libc_shim_init();
    return 0;
  }
  frida_flush_all_streams(&result);
  assert(result == 0 && allocations == 0);
  frida_libc_shim_init();
  assert(gum_calls == 1 && allocations == 2 && frida_libc_shim_initialized);
  assert(frida_streams == early_streams && frida_dirs == early_dirs);
  assert(frida_streams->n == 1 && frida_dirs->n == 1);
  frida_libc_shim_init();
  assert(gum_calls == 1 && allocations == 2);
  frida_flush_all_streams(&result);
  assert(result == 0 && early_file.flushed == 1 && closed_file.flushed == 0);
  frida_stdio_unregister_stream((FILE *) &early_file);
  frida_stdio_unregister_dir(&early_dir);
  assert(frida_streams->n == 0 && frida_dirs->n == 0);
  free(frida_streams); free(frida_dirs);
  frida_streams = frida_dirs = NULL;
  /* Exercise competing first registrations with a non-recursive mutex. */
  pthread_t threads[8]; FridaFile files[8] = {0};
  for (int i = 0; i < 8; i++)
    assert(pthread_create(&threads[i], NULL, register_concurrently, &files[i]) == 0);
  for (int i = 0; i < 8; i++) assert(pthread_join(threads[i], NULL) == 0);
  assert(allocations == 3 && frida_streams->n == 8);
  free(frida_streams);
  for (int i = 0; i < 3; i++) free(frida_stdio[i].impl);
  return 0;
}
