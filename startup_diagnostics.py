"""Opt-in Android startup diagnostics; apply before the normal source patches."""

from pathlib import Path

# No GLib, stdio, allocation, symbol lookup, or stack unwinding in this logger.
LOGGER = r"""
#ifdef __ANDROID__
#include <android/log.h>
#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

__attribute__((noinline, unused)) static void
PD_LOG (const char *event, void *caller)
{
  /* No TLS initialization or waiting: suppress nested/concurrent logger calls. */
  static unsigned char busy;
  if (__atomic_test_and_set (&busy, __ATOMIC_ACQUIRE))
    return;
  int saved_errno = errno;
  char message[384];
  char *out = message;
  const char *p;
  uintptr_t values[] = {
    (uintptr_t) syscall (SYS_gettid),
    (uintptr_t) __builtin_extract_return_addr (__builtin_return_address (0)),
    (uintptr_t) &PD_LOG,
    (uintptr_t) caller
  };
  const char *names[] = { " tid=0x", " site=0x", " anchor=0x", " caller=0x" };
  unsigned int i, n;

  for (p = event; *p != '\0' && out < message + 200; p++)
    *out++ = *p;
  for (i = 0; i != 4; i++)
  {
    for (p = names[i]; *p != '\0'; p++)
      *out++ = *p;
    for (n = sizeof (uintptr_t) * 2; n != 0; n--)
      *out++ = "0123456789abcdef"[(values[i] >> ((n - 1) * 4)) & 15];
  }
  *out = '\0';
  __android_log_write (ANDROID_LOG_ERROR, "PD-STARTUP", message);
  errno = saved_errno;
  __atomic_clear (&busy, __ATOMIC_RELEASE);
}
#define PD_CALLER __builtin_extract_return_addr (__builtin_return_address (0))
#define PD_EVENT(event) PD_LOG (event, PD_CALLER)
#define PD_NULL(table, event) do { if ((table) == NULL) PD_EVENT (event); } while (0)
#else
#define PD_EVENT(event) ((void) 0)
#define PD_NULL(table, event) ((void) 0)
#endif
"""

CONTRACTS = {
    "subprojects/frida-core/lib/payload/libc-shim.c": (
        "pd_stdio_log",
        [
            ("g_hash_table_add (frida_streams, stream);", "frida_streams", "streams-null", 1),
            ("g_hash_table_add (frida_dirs, dirp);", "frida_dirs", "dirs-null", 1),
        ],
    ),
    "subprojects/frida-gum/gum/guminterceptor.c": (
        "pd_interceptor_log",
        [
            (
                "g_hash_table_add (gum_interceptor_thread_contexts, context);",
                "gum_interceptor_thread_contexts",
                "thread-contexts-null",
                1,
            ),
            (
                "g_hash_table_insert (self->function_by_address, function_address, ctx);",
                "self->function_by_address",
                "functions-null",
                1,
            ),
            (
                "g_hash_table_insert (self->pending_update_tasks, start_page, pending);",
                "self->pending_update_tasks",
                "pending-start-null",
                1,
            ),
            (
                "g_hash_table_insert (self->pending_update_tasks, end_page, pending);",
                "self->pending_update_tasks",
                "pending-end-null",
                1,
            ),
        ],
    ),
    "subprojects/frida-gum/gum/gumcodeallocator.c": (
        "pd_allocator_log",
        [
            (
                "g_hash_table_add (self->dirty_pages, pages);",
                "self->dirty_pages",
                "dirty-pages-null",
                2,
            ),
        ],
    ),
    "subprojects/frida-gum/gum/gummemory.c": (
        "pd_memory_log",
        [
            (
                "g_hash_table_add (gum_softened_code_pages, (gpointer) cur_page);",
                "gum_softened_code_pages",
                "softened-pages-null",
                2,
            ),
        ],
    ),
}


def apply_startup_diagnostics(frida_dir: Path) -> None:
    """Validate every source contract before writing; reject drift/reapplication."""
    updates = {}
    for relative, (logger, contracts) in CONTRACTS.items():
        path = frida_dir / relative
        source = path.read_text()
        if "PD-STARTUP" in source:
            raise ValueError(f"Startup diagnostics already applied: {relative}")
        for old, table, event, count in contracts:
            if source.count(old) != count:
                raise ValueError(f"Startup diagnostic source mismatch: {relative}: {event}")
            # A compound statement preserves unbraced if/else semantics.
            source = source.replace(
                old, "{ PD_NULL (" + table + ', "' + event + '"); ' + old + " }"
            )
        if logger == "pd_stdio_log":
            for kind, arg_type, arg_name, table, event in [
                ("stream", "FILE", "stream", "frida_streams", "streams-null"),
                ("dir", "DIR", "dirp", "frida_dirs", "dirs-null"),
            ]:
                signature = (
                    f"static void\nfrida_stdio_register_{kind} ({arg_type} * {arg_name})\n"
                    "{\n  G_LOCK (frida_stdio);"
                )
                if source.count(signature) != 1:
                    raise ValueError(f"Startup diagnostic registration mismatch: {relative}")
                source = source.replace(
                    signature,
                    signature.replace(
                        "static void", "__attribute__((noinline)) static void"
                    ).replace("{\n", f'{{\n  PD_NULL ({table}, "{event}");\n'),
                )
                source = source.replace(
                    f'{{ PD_NULL ({table}, "{event}"); g_hash_table_add ({table}, {arg_name}); }}',
                    f"g_hash_table_add ({table}, {arg_name});",
                )
            for old, new in [
                (
                    "  if (frida_libc_shim_initialized)\n    return;\n\n  gum_init_embedded ();",
                    "  if (frida_libc_shim_initialized)\n"
                    "    return;\n"
                    "\n"
                    '  PD_EVENT ("shim-before-gum");\n'
                    "  gum_init_embedded ();\n"
                    '  PD_EVENT ("shim-after-gum");',
                ),
                (
                    "  frida_streams = g_hash_table_new (g_direct_hash, g_direct_equal);",
                    "  frida_streams = g_hash_table_new (g_direct_hash, g_direct_equal);\n"
                    '  PD_EVENT ("streams-created");',
                ),
            ]:
                if source.count(old) != 1:
                    raise ValueError(f"Startup diagnostic init mismatch: {relative}")
                source = source.replace(old, new)
        # Keep feature-test macros before system headers.
        offset = source.index("#include ")
        source = source[:offset] + LOGGER.replace("PD_LOG", logger) + source[offset:]
        source = source.replace("PD_LOG", logger)
        updates[path] = source
    for path, source in updates.items():
        path.write_text(source)
