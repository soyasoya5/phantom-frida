# phantom-frida

`phantom-frida` builds Android Frida Server and Gadget from source while
changing a targeted set of observable runtime identifiers. It is a builder and
verification harness, not a promise that every application-specific detection
method is defeated.

The current compatibility target is **Frida 17.16.4** on Android. Other Frida
versions are intentionally treated as unverified until their source contracts,
full build, and rooted-device acceptance have been repeated.

Use this project only on applications and devices you own or are authorized to
test.

## What is verified

The repository separates three kinds of evidence:

1. Unit and fixture tests validate input handling, exact Frida 17.16.4 source
   patch contracts, DEX rebuilding, artifact promotion, metadata, workflows,
   and failure behavior.
2. `build.py --verify` requires both Server and Gadget, strips the staged
   Gadget, then rejects known forbidden runtime markers before publishing
   either artifact.
3. `scripts/android_smoke.py` exercises a built artifact on one rooted device:
   authenticated abstract-UNIX transport, stock-client RPC, spawn, attach,
   Java bridge assertions, `/proc` checks, an external root memory scan, and a
   separately loaded Gadget.

A passing source test or byte scan is not equivalent to runtime stealth. Claims
about Android behavior should include the generated, redacted smoke-test report.

## Build with GitHub Actions

Run **Build Custom Frida** from the Actions tab. The reusable build workflow:

- validates every user-controlled build input;
- downloads Android NDK r29 from Google and checks its published checksum;
- clones a fresh upstream source tree instead of caching patched source;
- strips Gadget symbols and uploads only after the hard artifact and marker
  gates pass;
- includes `build-info.json` and `SHA256SUMS` in one build artifact.

The weekly workflow resolves the latest release through the authenticated
GitHub API, calls the same read-only build workflow, verifies the downloaded
artifact, attests it, and grants release write permission only to the final job.

## Local build

Requirements:

- Ubuntu 22.04 or newer (WSL is supported);
- Python 3.10 or newer;
- Git, curl, unzip, a C/C++ toolchain, JDK 17, and Node.js 18 or newer
  (CI uses Node.js 24.13.1);
- Android SDK platform and build-tools containing `android.jar` and D8;
- about 20 GB of free disk space.

If `--ndk-path` is omitted, the builder downloads Android NDK r29 under
`build/`. A verified pinned-input arm64 build is:

```bash
export ANDROID_SDK_ROOT=/path/to/Android/Sdk
python3 build.py \
  --version 17.16.4 \
  --name oemcodec \
  --arch android-arm64 \
  --port 27142 \
  --extended \
  --strict-wx \
  --verify
```

Useful options:

```text
--version, -v    Exact Frida semantic version (required)
--name, -n       Lowercase replacement name, 3-20 characters
--arch, -a       One or more supported Android architectures
--port, -p       Listening port; omitted keeps 27042
--extended, -e   Apply the optional extended identifier transformations
--strict-wx      Harden Frida-owned persistent anonymous RWX mappings on Android
--temp-fixes     Apply opt-in, device-specific stability changes
--verify         Reject known forbidden markers in final artifacts
--skip-build     Patch source without compiling
--skip-clone     Use an existing source tree in the work directory
--ndk-path       Use an existing Android NDK r29 directory
```

## Crash diagnosis symbols

Enable `debug_symbols` in Build Custom Frida, or pass `--debug-symbols` to
`build.py`. This configures `./configure --host=<arch> -- -Ddebug=true -Dstrip=true`.
The `--` separator is required by Frida's configure wrapper.

DWARF stays in the raw/modulated build outputs; Frida strips final agent/helper
assets before embedding them in the server. Published server and Gadget copies
are also stripped. The whole-file marker verifier remains enabled and unchanged.

The build artifact includes `<name>-symbols-<version>-<arch>.tar.gz`, containing
DWARF-bearing component ELFs and generated sources. Keep this archive and
`build-info.json` with the matching server. Reproduce the crash with that server;
symbol offsets from a different build are not reliable. Android uses ELF/DWARF,
not Windows PDB files.

Use the matching raw/modulated **agent** ELF for an agent crash, not the server:
`llvm-addr2line -C -f -i -e <agent-ELF> <relative-pc>`.

## Outputs and provenance

For the example above, `output/` contains:

```text
oemcodec-server-17.16.4-android-arm64
oemcodec-server-17.16.4-android-arm64.gz
oemcodec-gadget-17.16.4-android-arm64.so
oemcodec-gadget-17.16.4-android-arm64.so.gz
build-info.json
SHA256SUMS
```

`build-info.json` records the exact builder, Frida, and frida-core commits, NDK
version, UTC build time, architectures, name, port, strict W^X code-pool mode,
and workflow URL when built in Actions. Verify downloaded binary files before use:

```bash
cd output
sha256sum --check SHA256SUMS
python3 -m json.tool build-info.json >/dev/null
```

Public weekly releases also receive a GitHub build-provenance attestation.
`SHA256SUMS` identifies one output set; binary hashes are not expected to match
across different build hosts.

## Stock-client compatibility

The builder preserves the D-Bus protocol interfaces under `re.frida.*`, the
`/re/frida/GadgetSession` path, public capital `Frida` JavaScript API strings,
and generated C ABI symbols required by stock clients. Renaming those values
would break the normal Frida client/server contract.

The D-Bus service identifier, helper JNI package, zymbiote socket prefix,
selected process/library/path identifiers, selected thread names, and an
optional custom port are separate implementation details that the builder can
transform. The output verifier rejects this explicit marker set:

```text
frida\0
frida-zymbiote
re/frida/HelperBackend
frida-server
frida-helper
frida-agent
frida-gadget
frida-eternal-agent
frida-generate-certificate
frida-main-loop
frida:rpc
FridaScriptEngine
GLib-GIO
GDBusProxy
GumScript
Frida/
gum-js-loop
gmain\0
gdbus\0
pool-frida
pool-spawner
jit-cache\0
```

The exact public API string `Frida\0` and allowlisted `re.frida.*` protocol
identifiers remain intentionally preserved. The HTTP/Inspector prefix
`Frida/` is a verifier failure and is renamed independently.

## Rooted Android acceptance

Install the exact Python binding recorded in `build-info.json`, install the
pinned Java bridge dependency, and connect exactly one rooted Android device:

```bash
python3 -m pip install "frida==17.16.4" frida-tools
npm ci --ignore-scripts

python3 scripts/android_smoke.py \
  --server output/oemcodec-server-17.16.4-android-arm64 \
  --gadget output/oemcodec-gadget-17.16.4-android-arm64.so \
  --name oemcodec \
  --port 27142 \
  --package com.example.app \
  --ndk build/android-ndk-r29 \
  --report android-smoke-report.json
```

The package must be an installed Java application you are authorized to test.
The harness compiles `test_comprehensive.js` with the explicit
`frida-java-bridge` required by Frida 17. Server and Gadget each listen on a
random authenticated abstract-UNIX socket; their host TCP ports exist only as
ADB forwards and no device TCP listener is exposed. The harness also compiles
an ABI-matched root probe that scans the mapped agent and Gadget images through
`/proc/<pid>/mem`, outside Frida's own process view. It cleans up its processes,
forwards, and remote test directory on exit. The `/proc` gate also rejects
legacy `linjector` file-descriptor names and a non-zero `TracerPid`.

Frida Gadget configuration must be named next to the library as
`lib<name>-gadget.config.so`; the harness generates and deploys this file.

## Development checks

```bash
python -m pip install --requirement requirements-dev.txt
npm ci --ignore-scripts
python -m pytest
ruff check .
ruff format --check .
mypy build.py patches.py namegen.py scripts
node --check test_comprehensive.js
bash -n build-wsl.sh
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full evidence requirements.

## Repository layout

```text
build.py                 Clone, patch, compile, verify, and collect artifacts
patches.py               Source and same-length binary transformations
namegen.py               Seeded build-name and port generation
scripts/android_smoke.py Rooted Android Server/Gadget acceptance harness
test_comprehensive.js    Structured Frida 17 Java bridge assertions
tests/                   Unit, contract, fixture, and workflow tests
.github/workflows/       CI, CodeQL, reusable build, and release isolation
```

## Known boundaries

- Only Frida 17.16.4 is the current verification target; support is not inferred
  for all 17.x or 16.x releases.
- `--temp-fixes` changes runtime behavior and remains opt-in.
- Marker absence does not prove resistance to behavioral, integrity, timing, or
  application-specific detection.
- Stock-client compatibility preserves public ABI/protocol behavior. Active
  protocol probing and code-integrity checks may still identify instrumentation.
- This builder does not hide root, automated app launch, Interceptor code
  changes, user-script strings, or failures reported by remote attestation.
- `--strict-wx` separates the Android injector's executable code from writable
  data and stack pages, disables Gum's persistent RWX code pools, places GumJS
  `NativeCallback` closure code on dedicated RX pages while keeping libffi
  storage RW, and finalizes newly generated code as RX. If a matching remote
  libc is unavailable, the Android injector fails closed instead of using its
  upstream RWX fallback. It preserves pages that were already RWX and does not
  reject an explicit user-script request for RWX memory. A runtime `/proc/maps`
  sample does not prove that no transient RWX permission change occurs while
  executable code is being patched.
- The external memory gate scans the mapped agent/Gadget images for its explicit
  marker set; it is not a general-purpose scan of every anonymous heap page.
- Frida 17 raw agents need explicit bridge imports or bundling. The harness uses
  `frida.Compiler`; the Frida REPL and tracer provide their own bundled bridges.

## Credits and licensing

- [Frida](https://frida.re/) by Ole André Ravnas and contributors
- [ajeossida](https://github.com/hackcatml/ajeossida) by hackcatml

The builder code is MIT licensed. Generated binaries retain upstream licensing;
see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

### Android startup crash diagnostics

Enable **startup_diagnostics** in the manual build workflow, or pass
`--startup-diagnostics` to `build.py`. This automatically enables `--debug-symbols`.
For the reported 32-bit crash, select `android-arm` and Frida `17.16.4`.
Keep the other build options the same as the failing build.

The optional source patch logs to Android tag `PD-STARTUP`: libc-shim startup
stages and null tables at stream/directory registration, interceptor tables,
code allocator dirty pages, and softened code pages. Each message includes a
hexadecimal thread ID, a return address identifying the diagnostic call site,
the runtime address of a named logger function, and a separate `caller` return
address captured at the instrumentation site. Stream/directory registration is
marked `noinline`, so its caller identifies the path entering registration.
Other sites may still be inlined. It does not skip the
original insertion or fix the crash. It does not capture a complete backtrace.

Capture before reproducing, and stop with Ctrl+C afterward:

```sh
adb logcat -b all -v threadtime > frida-diagnostic.log
```

Retain the log, server, and symbols archive from this exact build. To resolve
addresses despite ASLR, find the ELF symbol value of the site's logger:
`pd_stdio_log`, `pd_interceptor_log`, `pd_allocator_log`, or `pd_memory_log`.
For ARM Thumb, clear bit 0 from the runtime anchor and ELF symbol value first.
Compute `load_bias = runtime_anchor - elf_logger_value`, then
`elf_site = (runtime_site & ~1) - load_bias`. Use the matching agent (or Gadget)
modulated ELF with `llvm-addr2line -f -C -i -e <elf> <elf_site>`; the site is a
return address immediately after the diagnostic call. Resolve `caller` using
the same load bias only when it belongs to the same ELF; callers outside that
module require their own mapping and symbols. Return addresses may resolve to
the line following the call.

These diagnostics use a fixed stack buffer and the native Android log writer,
with no GLib logging, stdio formatting, allocation, or runtime symbol lookup in
the logger itself. A nonblocking atomic guard per logger suppresses nested or
concurrent calls until the current log write completes; some messages may be
lost by design. Stream/directory diagnostics run before acquiring the stdio
mutex. Other sites may still hold internal locks: the guard prevents recursive
logger execution, but cannot prevent an external log writer from blocking or
re-entering a lock before reaching the guard. Android's log writer is still an external dependency, so this
is a diagnostic build, not a guarantee against changes in timing or reentrancy.
If no null-table message appears, the covered sites have not identified the
failure; the markers alone do not prove which table caused it. Source contract
mismatches stop patching before files are changed. Start from a fresh Frida tree.

### Early stream registration fix (Frida 17)

Frida's libc shim may register a stream while `gum_init_embedded()` is still
running, before its constructor creates the stream registry. Builds now always
apply a source fix for Frida 17 and later: stream and directory registration
lazily creates the corresponding registry under the existing stdio mutex, and
the constructor preserves registries populated during startup. An early
`fflush(NULL)` with no registry is a no-op. Gum's heap/allocator initialization
order is unchanged. The patch validates the expected source and fails on drift;
compatibility has been checked against 17.16.4 and 17.17.0.

No workflow checkbox is required for this fix. With `startup_diagnostics` enabled,
`streams-register-before-init` or `dirs-register-before-init` now describes the
handled early-registration path. `shim-after-gum` and `streams-created` indicate
that initialization progressed past the previously observed crash. Other
`*-null` diagnostics still indicate unhandled sites. A successful device test is
needed to establish whether the agent completes startup.
