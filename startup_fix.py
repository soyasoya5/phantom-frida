"""Fix Frida 17's libc-shim registry use during Gum initialization."""

from pathlib import Path

SHIM_PATH = "subprojects/frida-core/lib/payload/libc-shim.c"
FIX_MARKER = "/* Preserve registries populated during Gum initialization. */"


def patch_startup_registries(source: str) -> str:
    """Accept the pinned source with or without startup diagnostics; fail on drift."""
    if FIX_MARKER in source:
        raise ValueError("Startup registry fix already applied; use a fresh source tree")

    def replace_once(old: str, new: str) -> None:
        nonlocal source
        if source.count(old) != 1:
            raise ValueError(f"Startup registry source mismatch: {old.strip()}")
        source = source.replace(old, new)

    for table, item in [("frida_streams", "stream"), ("frida_dirs", "dirp")]:
        allocation = f"{table} = g_hash_table_new (g_direct_hash, g_direct_equal);"
        # The constructor must retain any table and entries created by early opens.
        replace_once(f"  {allocation}", f"  if ({table} == NULL)\n    {allocation}")
        # These insertion sites already hold the shared stdio mutex.
        insertion = f"  g_hash_table_add ({table}, {item});"
        replace_once(
            insertion,
            f"  if ({table} == NULL)\n    {allocation}\n\n" + insertion,
        )

    # fflush(NULL) before the first open has no registered streams to flush.
    flush_start = "static void\nfrida_flush_all_streams (int * result)\n{"
    if source.count(flush_start) != 1:
        raise ValueError("Startup registry source mismatch: flush function")
    offset = source.index(flush_start)
    end = source.index("\n}\n", offset) + len("\n}")
    old_flush = source[offset:end]
    if old_flush.count("  G_LOCK (frida_stdio);\n") != 1:
        raise ValueError("Startup registry source mismatch: flush lock")
    new_flush = old_flush.replace(
        "  G_LOCK (frida_stdio);\n",
        "  G_LOCK (frida_stdio);\n\n"
        "  if (frida_streams == NULL)\n"
        "  {\n"
        "    G_UNLOCK (frida_stdio);\n"
        "    return;\n"
        "  }\n",
    )
    source = source[:offset] + new_flush + source[end:]

    # With the fix, early registration is expected and no longer implies a crash.
    for table, old, new in [
        ("frida_streams", "streams-null", "streams-register-before-init"),
        ("frida_dirs", "dirs-null", "dirs-register-before-init"),
    ]:
        source = source.replace(f'PD_NULL ({table}, "{old}");', f'PD_NULL ({table}, "{new}");')
    return FIX_MARKER + "\n" + source


def apply_startup_registry_fix(frida_dir: Path) -> None:
    path = frida_dir / SHIM_PATH
    # No write takes place unless every source contract has passed.
    patched = patch_startup_registries(path.read_text(encoding="utf-8"))
    path.write_text(patched, encoding="utf-8")
