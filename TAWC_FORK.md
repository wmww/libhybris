# tawc libhybris fork

This fork is claudeslop: AI-written and AI-maintained as part of the [tawc](https://codeberg.org/sphi/tawc) project.

**Fork URL:** https://github.com/wmww/libhybris

## Purpose

Provide EGL/GLES access to Android GPU drivers from glibc programs running in a chroot, specifically for tawc's Wayland compositor. The key goal is running on **stock Android firmware** (no patched bionic/vendor images).

## Patches on top of upstream

Eight committed patches on top of [upstream libhybris](https://github.com/libhybris/libhybris), grouped into six problem areas, all aimed at making stock (unpatched) Android firmware usable from a glibc chroot. Plus pending (uncommitted) Vulkan-related changes described at the end.

### TLS thunk patcher

Some Android GPU drivers (originally noticed with Mali's `libGLES_mali.so`, later confirmed for Adreno) access hardcoded bionic TLS slots via `mrs TPIDR_EL0` + fixed offset. The access is inlined by the compiler, so it can't be redirected by symbol overriding. Under glibc those slots are not reserved, so the driver and the host process stomp on each other's TLS. Originated in lindroid-drm by Nikita Ukhrenkov; imported and extended here.

- **`hybris: introduce thunk-based TLS access patcher for aarch64`**. Scans loaded libhybris-mapped code for `mrs TPIDR_EL0` instructions and replaces each with a branch to a dynamically-generated thunk (read TPIDR_EL0 → add libhybris TLS offset → branch back). Thunks are allocated adjacent to each library so the ±128MB branch range is respected. Originally gated on `HYBRIS_TLS_PATCH=1` (optionally a library allowlist).

- **`TLS patcher: exact-size thunk regions, 24-bit ADD encoding, fatal on failure`**. Three bugs in the original patcher made it silently miss patches or abort outright: a fixed 32-slot thunk region array dropped registrations past library #32 (Adreno loads 80+); fixed 64KB thunk regions couldn't hold all patches for very large libraries (e.g. `libllvm-glnext.so` has 4920 MRS instructions); and the thunk applied the glibc→hybris TLS offset with a single unshifted ADD, limiting the encodable offset to 12 bits (0..4095), which aborted during library load when glibc's static TLS block plus dynamically-allocated `__thread` vars pushed the offset past 4 KB (seen with SuperTuxKart at 5728 bytes). Rewritten as a two-pass scan (count MRS, allocate an exactly-sized thunk region, then patch); all patching errors now fatal instead of silent; reserves 4× code size of VA space (PROT_NONE, no physical backing) to guarantee the thunk region sits adjacent. Two ADDs (low 12 bits unshifted + high 12 bits with `sh=1`, LSL #12) extend the encodable offset to 16 MB while keeping the 4-instruction / 16-byte thunk footprint.

- **`Remove HYBRIS_PATCH_TLS env var, always enable TLS patching on aarch64`**. The patcher turned out to be required for every GPU stack tested on stock firmware, so the opt-in env var became foot-gun-shaped. Always-on on aarch64; the env var is gone.

### bionic_tls compat for stock firmware

- **`hooks: bionic_tls compat for stock Android firmware`**. Stock bionic reads `TLS_SLOT_BIONIC_TLS` (slot `-1`, at `TPIDR_EL0 - 8`), expecting a ~12KB `bionic_tls` struct. The TLS thunk patcher alone isn't enough: even correctly redirected, slot `-1` lands on `tls_hooks[-1]` which is NULL → SIGSEGV. Fix: replace the flat `tls_hooks[16]` with a struct that has a `bionic_tls_ptr` pre-slot, lazy-allocate a 16KB zero-filled `bionic_tls` per thread, and wrap `pthread_create` to initialize it before bionic code runs on new threads. This is the commit that makes stock (non-Halium) firmware work without patched vendor images.

### CFI slowpath bypass

- **`linker q: patch bionic __cfi_slowpath when loading vendor libraries`**. Android vendor libraries are CFI-instrumented: indirect calls go through `__cfi_slowpath` in bionic's `libdl.so`, which looks up the target in a sparse shadow table. That shadow is built by the bionic linker at process start, covering only system libraries — vendor libraries loaded later via `hybris_dlopen` are missing from it, and any CFI-checked indirect call into them then crashes inside `__cfi_slowpath`. Fix: find `libdl.so` in `/proc/self/maps`, walk its in-memory ELF headers and dynamic symbol table to locate `__cfi_slowpath` (guaranteed dynamically exported on any Android with CFI — Clang emits direct calls to this exact symbol from every CFI-instrumented binary), and overwrite its first instruction with `ret` (`0xd65f03c0`). Uses RW → write → RX mprotect sequence (avoids W+X, which some SELinux policies deny) and `sysconf(_SC_PAGESIZE)` (16K-page-ready). Equivalent to the shadow marking the range `kUncheckedShadow`, which is what would happen anyway since vendor libraries lack `__cfi_check`. Called from `android_linker_init()` and from `link_image()` after each library is loaded — the first call is usually too early (libdl isn't mapped yet), but a later call succeeds once a vendor library pulls libdl in via DT_NEEDED. Idempotent via a static flag.

### Attach buffers to wl_surface from queueBuffer, not finishSwap

- **`wayland-egl: attach+commit inside queueBuffer so drivers that skip eglSwapBuffers still submit`**. Upstream libhybris splits the "submit a frame" work in two: `dequeueBuffer`/`queueBuffer` (called by the GL driver from the ANativeWindow API) just push the buffer into an internal `queue` deque, and the actual `wl_surface_attach` + `wl_surface_damage*` + `wl_surface_commit` happens later in `ws_finishSwap`, which is invoked from libhybris's `eglSwapBuffers` wrapper. That works for normal GL apps where every frame goes through `eglSwapBuffers`. It breaks on Qualcomm Adreno with Firefox/WebRender: the Renderer thread pushes frames through the ANativeWindow API from a driver-internal worker thread that never calls `eglSwapBuffers` on that wl_surface, so `ws_finishSwap` is never invoked, `queue` grows unboundedly, no `wl_surface.commit` is sent, and the compositor sees nothing (confirmed: black screen on Pixel 4a Adreno 618). Fix: factor the attach/damage/commit logic out of `finishSwap` into a `drainOneQueuedBufferLocked()` helper, and call it both from `finishSwap` (the normal path) and at the end of `queueBuffer` (after the fence wait). In the normal `eglSwapBuffers` path `ws_finishSwap` now finds the queue already drained — it becomes a no-op on the attach side but still handles the throttle/frame-callback wait, preserving upstream's swap-interval semantics. In the driver-internal-thread path the submit happens immediately, no `eglSwapBuffers` required. Damage stashed by `prepareSwap` is consumed on the first drain and cleared, so a late `finishSwap` can't re-apply stale rects. Only touches `hybris/egl/platforms/wayland/wayland_window.cpp` and `wayland_window.h`.

### NATIVE_WINDOW_BUFFER_AGE: return 0 instead of hardcoded 2

- **`nativewindow: return NATIVE_WINDOW_BUFFER_AGE=0 (content undefined)`**. Upstream libhybris's `BaseNativeWindow::_query(NATIVE_WINDOW_BUFFER_AGE)` in `hybris/platforms/common/nativewindowbase.cpp` returned a hardcoded `*value = 2` (with a "sure :)" comment in the original). That value is what the vendor EGL driver returns for `eglQuerySurface(EGL_BUFFER_AGE_EXT)`. Clients that trust it — including Firefox/WebRender with partial-present enabled — assume the just-dequeued buffer's content is exactly what was on screen 2 frames ago, and layer their incremental damage on top. With a 3-slot pool the actual pool-slot age is unrelated to the reported 2, so damage gets composited over stale pixels from whichever earlier frame happened to land in that slot, producing a visible A-B-A-B alternation (Firefox hamburger menu on Wikipedia reliably triggered it). Fix: return `0`, which per `EGL_EXT_buffer_age` means "buffer content is undefined" — clients must redraw the whole surface. An accurate per-slot age would be ideal but requires tracking last-swap-serial per buffer; `0` is always correct, just turns partial-present off. Single-line change in `nativewindowbase.cpp`.

### EGL_EXT_device_query stubs for Firefox glxtest

- **`egl: stub eglQueryDeviceStringEXT/eglQueryDisplayAttribEXT`**. Firefox's startup probe (`/usr/lib/firefox/glxtest -w`, source `toolkit/xre/glxtest/glxtest.cpp`) does an `eglGetProcAddress` null-check on `eglQueryDeviceStringEXT` and crashes on `eglQueryDisplayAttribEXT` if it's NULL. Both are part of `EGL_EXT_device_query`, a desktop/Mesa extension for introspecting DRM render nodes — Android EGL never implements it, so libhybris's `eglGetProcAddress` legitimately returned NULL and Firefox concluded "EGL test failed", `ForceDisable`'d `Feature::HW_COMPOSITING`, and rendered everything via SHM. Fix: add `_my_eglQueryDeviceStringEXT` (returns `NULL`) and `_my_eglQueryDisplayAttribEXT` (returns `EGL_FALSE`) to the `_eglHybrisOverrideFunctions` table in `hybris/egl/egl.c`. The stubs honestly report "no device-query info available" — every consumer null-checks results, and we still don't advertise `EGL_EXT_device_query` in any extension string, so callers that respect the extension string see truthful behaviour. Only callers like Firefox that bypass the extension string and `dlsym`-by-procaddr see the stubs.

### AHB gralloc backend

- **`gralloc: add AHardwareBuffer backend preferred over GRALLOC_COMPAT/1/0`**. Upstream libhybris has no gralloc of its own — `hybris/gralloc/gralloc.c` dispatches every call to one of three backends (GRALLOC_COMPAT via `libui_compat_layer.so`, GRALLOC1 via `hw_get_module`, GRALLOC0). On stock Android ≥ 12 where Halium's `libui_compat_layer.so` isn't present, libhybris falls back to vendor gralloc1, which on modern devices (gralloc4 mapper) produces handles with the legacy `private_handle_t` layout (`fds=1 ints=8`) — the Android-side mapper rejects them with `ver(12/12) ints(8/23) fds(1/2)` and any consumer in any other process (our Wayland compositor, or even the same vendor EGL in a different linker namespace) fails to import them. Fix: add a fourth backend (`version=3`) that routes allocate / retain / release / lock / unlock through the public NDK `AHardwareBuffer_*` API from `libnativewindow.so`. Handles are gralloc4-format by construction, cross-process import "just works" via `AHardwareBuffer_createFromHandle`, and we don't need a Halium compat blob. Preferred over all other backends when `libnativewindow.so` resolves. A handle↔AHB map with a shadow refcount bridges the gap between gralloc's handle-keyed API and AHB's pointer-keyed API. `hybris_gralloc_import_buffer` returns `-ENOSYS` in AHB mode because the signature doesn't carry the `AHardwareBuffer_Desc` fields `createFromHandle` needs; the only caller is server-side-buffer-allocation, which we disable via `--disable-wayland_serverside_buffers`. Framebuffer callers still route through GRALLOC0 (AHB has no framebuffer-device ops).

Together these give us working EGL 1.5 on Pixel 4a (Adreno 618) and OnePlus 9 (Adreno 660) running stock LineageOS Android 16, and interoperable gralloc buffers across the libhybris-in-chroot ↔ Android-side-compositor boundary.

## Pending Vulkan changes (uncommitted)

Changes currently in the working tree, needed for Vulkan clients via `HYBRIS_VULKANPLATFORM=wayland` to display on-screen through a tawc compositor. Verified end-to-end on OnePlus 9 (2026-04-20).

### IFUNC → assembly trampoline (`vulkan.c`)

Replaces the `gnu_indirect_function` (IFUNC) dispatch for every Vulkan entry point with an arm64 assembly trampoline (`adrp+ldr+br x16`) resolved by a `__attribute__((constructor))`. The IFUNC resolver ran during the dynamic linker's relocation phase and called `android_dlopen()` to load the Android Vulkan driver — this crashes when triggered alongside complex library trees (e.g. GTK4 links `libvulkan.so.1` at build time, pulling the IFUNC resolvers before `android_dlopen` is safe). The constructor defers resolution until after relocation completes.

### Cuda NV guard (`vulkan.c`)

`#if VK_HEADER_VERSION >= 269` → `#ifdef VK_NV_cuda_kernel_launch`. In `vulkan-headers` 1.4.341 (current Arch) the NV Cuda symbols (`vkCreateCudaModuleNV` et al.) got pulled out of `vulkan_core.h` and now live behind the extension's own feature-test macro. The old version-number guard produced undefined references at link time. Keying off the extension macro is the portable fix.

### Fence wait before attach+commit (`wayland_window.cpp`)

Moves the `presentBuffer(wnb)` call from *before* the `sync_wait(fenceFd)` to *after* it inside `WaylandNativeWindow::queueBuffer`. Upstream did `wl_surface.attach` + `wl_surface.commit` *before* waiting on the Vulkan fence, which is a correctness bug: Wayland has no per-commit fence mechanism, so once the commit is sent the compositor is free to sample the buffer, and on a fast client or a slow GPU that sample happens before the GPU finishes writing. Swapping the order makes the commit always follow GPU completion.

### X11/Xcb stubs (`vulkan.c`)

Stub `vkCreateXlibSurfaceKHR`, `vkGetPhysicalDeviceXlibPresentationSupportKHR`, `vkCreateXcbSurfaceKHR`, `vkGetPhysicalDeviceXcbPresentationSupportKHR` that return `VK_ERROR_EXTENSION_NOT_PRESENT` / `VK_FALSE`. Needed because some clients/libraries (SDL, GLFW) reference these symbols at link time even when using the Wayland backend.

### Surface capabilities patching + swapchain resize (`vulkanplatform_wayland.cpp`, `vulkan.c`, `ws.c`, `ws.h`)

The Android driver reports `currentExtent` based on the ANativeWindow's size, which starts at 1×1 (the initial `wl_egl_window_create` size). Vulkan clients that use `currentExtent` for their swapchain image extent create a 1×1 swapchain — invisible on screen.

Fix follows the Vulkan spec for Wayland WSI: `patchSurfaceCapabilities` overrides `currentExtent` to `{0xFFFFFFFF, 0xFFFFFFFF}` (undefined — lets the app choose its own size) and raises `maxImageExtent` to 16384. `prepareSwapchain` resizes the `WaylandNativeWindow` to match the app's chosen extent at `vkCreateSwapchainKHR` time, so the Android driver creates correctly-sized buffers. Both `vkGetPhysicalDeviceSurfaceCapabilitiesKHR` and `vkGetPhysicalDeviceSurfaceCapabilities2KHR` are intercepted. `vkGetInstanceProcAddr` and `vkGetDeviceProcAddr` return the wrapped versions so dynamic dispatch also works.

## History

Git history is kept clean (commits are rebased/amended, not appended). Each update is tagged `tawc-DD-Mon-YYYY-N` (e.g. `tawc-15-Apr-2026-1`) so previous states can be recovered even after force-pushes.

## Build

Built via the tawc project (not scripts in this repo):

```
# from the tawc repo root:
bash client/build-libhybris [--clean]
```

Syncs local `./libhybris` to the phone and builds inside the Arch chroot. See `client/build-libhybris` in the tawc repo for details.
