/* Excerpts from frida-core 17.16.4/lib/payload/libc-shim.c.
 * Upstream license: wxWindows Library Licence, Version 3.1.
 * Used by the host startup lifecycle regression harness.
 */

__attribute__ ((constructor)) static void
frida_libc_shim_init (void)
{
  FridaFile * f0, * f1, * f2;

  if (frida_libc_shim_initialized)
    return;

  gum_init_embedded ();

  f0 = NULL;
  f1 = NULL;
  f2 = NULL;

  G_LOCK (frida_stdio);

  frida_streams = g_hash_table_new (g_direct_hash, g_direct_equal);
#ifdef HAVE_FRIDA_DIR
  frida_dirs = g_hash_table_new (g_direct_hash, g_direct_equal);
#endif

  G_UNLOCK (frida_stdio);

  f0 = frida_file_new (0, FALSE, _IOFBF);
#ifndef FRIDA_STDIO_OPAQUE_FILE
  frida_file_bind_slot (&__sF[0], f0);
#else
  frida_file_bind_slot ((FILE *) &frida_stdio[0], f0);
#endif

  f1 = frida_file_new (1, FALSE, _IOLBF);
#ifndef FRIDA_STDIO_OPAQUE_FILE
  frida_file_bind_slot (&__sF[1], f1);
#else
  frida_file_bind_slot ((FILE *) &frida_stdio[1], f1);
#endif

  f2 = frida_file_new (2, FALSE, _IONBF);
#ifndef FRIDA_STDIO_OPAQUE_FILE
  frida_file_bind_slot (&__sF[2], f2);
#else
  frida_file_bind_slot ((FILE *) &frida_stdio[2], f2);
#endif

  frida_libc_shim_initialized = TRUE;
}

static void
frida_stdio_register_stream (FILE * stream)
{
  G_LOCK (frida_stdio);

  g_hash_table_add (frida_streams, stream);

  G_UNLOCK (frida_stdio);
}

static void
frida_stdio_unregister_stream (FILE * stream)
{
  G_LOCK (frida_stdio);

  g_hash_table_remove (frida_streams, stream);

  G_UNLOCK (frida_stdio);
}

static void
frida_stdio_register_dir (DIR * dirp)
{
  G_LOCK (frida_stdio);

  g_hash_table_add (frida_dirs, dirp);

  G_UNLOCK (frida_stdio);
}

static void
frida_stdio_unregister_dir (DIR * dirp)
{
  G_LOCK (frida_stdio);

  g_hash_table_remove (frida_dirs, dirp);

  G_UNLOCK (frida_stdio);
}

static void
frida_flush_all_streams (int * result)
{
  GHashTableIter iter;
  gpointer key;

  G_LOCK (frida_stdio);

  g_hash_table_iter_init (&iter, frida_streams);

  while (g_hash_table_iter_next (&iter, &key, NULL))
  {
    FILE * s = key;
    FridaFile * f;

    f = frida_file_get_impl (s);

    if (frida_file_flush_write (f) != 0)
      *result = EOF;
  }

  G_UNLOCK (frida_stdio);
}
