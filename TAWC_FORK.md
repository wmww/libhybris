# tawc libhybris fork

This fork is claudeslop: AI-written and AI-maintained as part of the [tawc](https://codeberg.org/sphi/tawc) project.

**Fork URL:** https://github.com/wmww/libhybris

## Purpose

Provide EGL/GLES access to Android GPU drivers from glibc programs running in a chroot, specifically for tawc's Wayland compositor. The key goal is running on **stock Android firmware** (no patched bionic/vendor images).

## Patches on top of upstream

Five commits on top of [upstream libhybris](https://github.com/libhybris/libhybris), grouped into three problem areas, all aimed at making stock (unpatched) Android firmware usable from a glibc chroot. Commits are listed oldest-first with their current short hash.

### TLS thunk patcher

Some Android GPU drivers (originally noticed with Mali's `libGLES_mali.so`, later confirmed for Adreno) access hardcoded bionic TLS slots via `mrs TPIDR_EL0` + fixed offset. The access is inlined by the compiler, so it can't be redirected by symbol overriding. Under glibc those slots are not reserved, so the driver and the host process stomp on each other's TLS. Originated in lindroid-drm by Nikita Ukhrenkov; imported and extended here.

- **`hybris: introduce thunk-based TLS access patcher for aarch64`** (`77bda7a`). Scans loaded libhybris-mapped code for `mrs TPIDR_EL0` instructions and replaces each with a branch to a dynamically-generated thunk (read TPIDR_EL0 → add libhybris TLS offset → branch back). Thunks are allocated adjacent to each library so the ±128MB branch range is respected. Originally gated on `HYBRIS_TLS_PATCH=1` (optionally a library allowlist).

- **`TLS patcher: exact-size thunk regions, fatal errors on failure`** (`1c770c5`). Two bugs in the original patcher made it silently miss patches on large GPU stacks: a fixed 32-slot thunk region array dropped registrations past library #32 (Adreno loads 80+), and fixed 64KB thunk regions couldn't hold all patches for very large libraries (e.g. `libllvm-glnext.so` has 4920 MRS instructions). Rewritten as a two-pass scan (count MRS, then allocate an exactly-sized thunk region), with all patching errors now fatal instead of silent. Reserves 4× code size of VA space (PROT_NONE, no physical backing) to guarantee the thunk region can sit adjacent.

- **`Remove HYBRIS_PATCH_TLS env var, always enable TLS patching on aarch64`** (`7fcb352`). The patcher turned out to be required for every GPU stack tested on stock firmware, so the opt-in env var became foot-gun-shaped. Always-on on aarch64; the env var is gone.

### bionic_tls compat for stock firmware

- **`hooks: bionic_tls compat for stock Android firmware`** (`740de42`). Stock bionic reads `TLS_SLOT_BIONIC_TLS` (slot `-1`, at `TPIDR_EL0 - 8`), expecting a ~12KB `bionic_tls` struct. The TLS thunk patcher alone isn't enough: even correctly redirected, slot `-1` lands on `tls_hooks[-1]` which is NULL → SIGSEGV. Fix: replace the flat `tls_hooks[16]` with a struct that has a `bionic_tls_ptr` pre-slot, lazy-allocate a 16KB zero-filled `bionic_tls` per thread, and wrap `pthread_create` to initialize it before bionic code runs on new threads. This is the commit that makes stock (non-Halium) firmware work without patched vendor images.

### CFI slowpath bypass

- **`linker q: patch bionic __cfi_slowpath when loading vendor libraries`** (`4a87d9b`). Android vendor libraries are CFI-instrumented: indirect calls go through `__cfi_slowpath` in bionic's `libdl.so`, which looks up the target in a sparse shadow table. That shadow is built by the bionic linker at process start, covering only system libraries — vendor libraries loaded later via `hybris_dlopen` are missing from it, and any CFI-checked indirect call into them then crashes inside `__cfi_slowpath`. Fix: find `libdl.so` in `/proc/self/maps`, walk its in-memory ELF headers and dynamic symbol table to locate `__cfi_slowpath` (guaranteed dynamically exported on any Android with CFI — Clang emits direct calls to this exact symbol from every CFI-instrumented binary), and overwrite its first instruction with `ret` (`0xd65f03c0`). Uses RW → write → RX mprotect sequence (avoids W+X, which some SELinux policies deny) and `sysconf(_SC_PAGESIZE)` (16K-page-ready). Equivalent to the shadow marking the range `kUncheckedShadow`, which is what would happen anyway since vendor libraries lack `__cfi_check`. Called from `android_linker_init()` and from `link_image()` after each library is loaded — the first call is usually too early (libdl isn't mapped yet), but a later call succeeds once a vendor library pulls libdl in via DT_NEEDED. Idempotent via a static flag.

Together these give us working EGL 1.5 on Pixel 4a (Adreno 618) running stock LineageOS Android 16.

## Build

Built via the tawc project (not scripts in this repo):

```
# from the tawc repo root:
bash client/build-libhybris [--clean]
```

Syncs local `./libhybris` to the phone and builds inside the Arch chroot. See `client/build-libhybris` in the tawc repo for details.
