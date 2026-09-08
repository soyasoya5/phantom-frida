import shutil
import subprocess
from pathlib import Path

import pytest

from startup_diagnostics import CONTRACTS, apply_startup_diagnostics
from startup_fix import SHIM_PATH, apply_startup_registry_fix, patch_startup_registries

FIXTURE = Path(__file__).parent / "fixtures/frida-17.16.4/libc-shim-startup.c"


def test_registration_during_gum_init_and_concurrent_first_use(tmp_path):
    cc = shutil.which("cc")
    if cc is None:
        pytest.skip("C compiler required")
    harness = (FIXTURE.parent.parent / "startup-registry-harness.c").read_text()
    for patched in [False, True]:
        source = FIXTURE.read_text()
        if patched:
            source = patch_startup_registries(source)
        source = source.replace("__attribute__ ((constructor)) ", "")
        cfile = tmp_path / f"probe-{patched}.c"
        exe = cfile.with_suffix("")
        cfile.write_text(harness.replace("/* UPSTREAM_FUNCTIONS */", source))
        subprocess.run(
            [cc, "-O2", "-Wall", "-Wextra", "-Werror", "-pthread", str(cfile), "-o", str(exe)],
            check=True,
        )
        if patched:
            subprocess.run([str(exe)], check=True, timeout=10)
        else:
            result = subprocess.run(
                [str(exe), "early-open"], capture_output=True, text=True, timeout=10
            )
            assert result.returncode != 0
            assert "registration needs an initialized registry" in result.stderr


def test_drift_does_not_write(tmp_path):
    path = tmp_path / SHIM_PATH
    path.parent.mkdir(parents=True)
    source = FIXTURE.read_text().replace("g_hash_table_add (frida_dirs, dirp);", "changed ();")
    path.write_text(source)
    with pytest.raises(ValueError, match="source mismatch"):
        apply_startup_registry_fix(tmp_path)
    assert path.read_text() == source


def test_reapplication_rejected():
    patched = patch_startup_registries(FIXTURE.read_text())
    with pytest.raises(ValueError, match="already applied"):
        patch_startup_registries(patched)


def test_diagnostics_then_fix(tmp_path):
    for relative, (logger, contracts) in CONTRACTS.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        source = "#include <stdio.h>\n"
        if logger == "pd_stdio_log":
            source += FIXTURE.read_text()
        else:
            source += "\n".join(old for old, _, _, count in contracts for _ in range(count))
        path.write_text(source)
    apply_startup_diagnostics(tmp_path)
    apply_startup_registry_fix(tmp_path)
    source = (tmp_path / SHIM_PATH).read_text()
    assert "streams-register-before-init" in source
    assert "dirs-register-before-init" in source
    assert '"streams-null"' not in source
    assert '"shim-after-gum"' in source
    assert source.count("if (frida_streams == NULL)") == 3
    assert source.count("if (frida_dirs == NULL)") == 2
