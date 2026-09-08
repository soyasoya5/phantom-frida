import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

import build


def test_debug_build_keeps_production_stripping(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(build, "run", lambda command, **kwargs: calls.append(command))
    build.configure_arch(tmp_path, "android-arm", tmp_path, debug_symbols=True)
    assert calls[0] == ["./configure", "--host=android-arm", "--", "-Ddebug=true", "-Dstrip=true"]


def test_runtime_is_stripped_but_archive_keeps_dwarf(monkeypatch, tmp_path):
    cc, strip, readelf = (shutil.which(tool) for tool in ("cc", "strip", "readelf"))
    if not all((cc, strip, readelf)):
        pytest.skip("C toolchain required")
    source = tmp_path / "frida-agent.c"
    source.write_text(
        "typedef int GDBusProxy; static GDBusProxy frida;\nint main(void) { return frida; }\n"
    )
    root = tmp_path / "frida"
    core = root / "build/subprojects/frida-core"
    raw = core / "server/waxxer-server-raw"
    raw.parent.mkdir(parents=True)
    subprocess.run([cc, "-g", str(source), "-o", str(raw)], check=True)
    assert build.scan_forbidden_markers(raw)
    for relative in (
        "server/waxxer-server",
        "lib/agent/libwaxxer-agent-raw.so",
        "lib/gadget/libwaxxer-gadget.so",
    ):
        dest = core / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(raw, dest)
    raw_bytes = raw.read_bytes()
    monkeypatch.setattr(build, "apply_binary_patches", lambda *args: None)
    output = tmp_path / "output"
    build.collect_artifacts(
        root, "android-arm", "waxxer", "17.16.4", output, False, strip_tool=Path(strip)
    )
    build.verify_binary(output / "waxxer-server-17.16.4-android-arm")
    assert raw.read_bytes() == raw_bytes
    archive = build.collect_debug_symbols(
        root, output, "waxxer", "17.16.4", "android-arm", Path(readelf)
    )
    with tarfile.open(archive) as bundle:
        assert (
            bundle.extractfile("build/subprojects/frida-core/server/waxxer-server-raw").read()
            == raw_bytes
        )


def test_real_runtime_markers_are_still_rejected(tmp_path):
    binary = tmp_path / "binary"
    binary.write_bytes(b"GDBusProxy\0")
    with pytest.raises(build.BuildError, match="GDBusProxy"):
        build.verify_binary(binary)
