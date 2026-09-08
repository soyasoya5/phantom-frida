import shutil
import subprocess

import pytest

from startup_diagnostics import CONTRACTS, LOGGER, apply_startup_diagnostics


def fixture_tree(root):
    for relative, (logger, contracts) in CONTRACTS.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        source = "#define _GNU_SOURCE\n#include <stdio.h>\n"
        if logger != "pd_stdio_log":
            source += "\n".join(old for old, _, _, count in contracts for _ in range(count))
        if logger == "pd_stdio_log":
            for kind, typ, arg in [("stream", "FILE", "stream"), ("dir", "DIR", "dirp")]:
                source += (
                    f"\nstatic void\nfrida_stdio_register_{kind} ({typ} * {arg})\n"
                    "{\n  G_LOCK (frida_stdio);\n"
                    + next(old for old, _, event, _ in contracts if event == f"{kind}s-null")
                    + "\n}\n"
                )
            source += (
                "\n"
                "  if (frida_libc_shim_initialized)\n"
                "    return;\n"
                "\n"
                "  gum_init_embedded ();\n"
                "  frida_streams = g_hash_table_new (g_direct_hash, g_direct_equal);\n"
                ""
            )
        path.write_text(source)


def test_drift_is_atomic(tmp_path):
    fixture_tree(tmp_path)
    paths = [tmp_path / name for name in CONTRACTS]
    paths[-1].write_text("#include <stdio.h>\n")
    before = [p.read_bytes() for p in paths]
    with pytest.raises(ValueError, match="source mismatch"):
        apply_startup_diagnostics(tmp_path)
    assert [p.read_bytes() for p in paths] == before


def test_reapplication_rejected(tmp_path):
    fixture_tree(tmp_path)
    apply_startup_diagnostics(tmp_path)
    shim = (tmp_path / "subprojects/frida-core/lib/payload/libc-shim.c").read_text()
    for kind, table in [("stream", "frida_streams"), ("dir", "frida_dirs")]:
        assert f"__attribute__((noinline)) static void\nfrida_stdio_register_{kind}" in shim
        assert f'PD_NULL ({table}, "{kind}s-null");\n  G_LOCK' in shim
    with pytest.raises(ValueError, match="already applied"):
        apply_startup_diagnostics(tmp_path)


def test_logger(tmp_path):
    cc = shutil.which("cc")
    if cc is None:
        pytest.skip("C compiler required")
    header = tmp_path / "android/log.h"
    header.parent.mkdir()
    header.write_text(
        "#define ANDROID_LOG_ERROR 6\nint __android_log_write(int, const char *, const char *);\n"
    )
    source = (
        "#define _GNU_SOURCE\n"
        + LOGGER
        + r"""
#include <assert.h>
#include <string.h>
#include <stdio.h>
static int logs, inserts;
int __android_log_write(int level, const char *tag, const char *message) {
  assert(level == 6 && strcmp(tag, "PD-STARTUP") == 0);
  assert(strstr(message, "streams-null tid=0x") != NULL);
  assert(strstr(message, " site=0x") && strstr(message, " anchor=0x"));
  logs++;
  /* Simulate Android logging synchronously re-entering this logger. */
  PD_EVENT("nested-must-not-log");
  puts(message);
  errno = EIO; return 0;
}
__attribute__((noinline)) static void registration(void) {
  PD_NULL(NULL, "streams-null");
  inserts++;
}
__attribute__((noinline)) static void open_path(void) {
  registration();
  inserts++;
}
int main(void) {
  void *table = NULL;
  errno = EINVAL;
  if (1) { PD_NULL(table, "streams-null"); inserts++; } else inserts += 100;
  assert(logs == 1 && inserts == 1 && errno == EINVAL);
  table = &logs;
  PD_NULL(table, "must-not-log");
  assert(logs == 1);
  open_path();
  assert(logs == 2 && inserts == 3 && errno == EINVAL);
  return 0;
}
"""
    )
    cfile = tmp_path / "probe.c"
    cfile.write_text(source)
    exe = tmp_path / "probe"
    subprocess.run(
        [
            cc,
            "-D__ANDROID__",
            "-O2",
            "-g",
            "-no-pie",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(tmp_path),
            str(cfile),
            "-o",
            str(exe),
        ],
        check=True,
    )
    result = subprocess.run([str(exe)], check=True, capture_output=True, text=True)
    lines = result.stdout.splitlines()
    assert len(lines) == 2  # Recursive logging was suppressed and the guard reset.
    addr2line = shutil.which("addr2line")
    if addr2line is not None:
        caller = lines[-1].split("caller=", 1)[1]
        resolved = subprocess.check_output([addr2line, "-f", "-e", str(exe), caller], text=True)
        assert resolved.splitlines()[0] == "open_path"
