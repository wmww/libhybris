# tawc libhybris fork

This fork is claudeslop: AI-written and AI-maintained as part of the [tawc](https://codeberg.org/sphi/tawc) project.

**Fork URL:** https://github.com/wmww/libhybris

## Purpose

Provide EGL/GLES access to Android GPU drivers from glibc programs running in a chroot, specifically for tawc's Wayland compositor. The key goal is running on **stock Android firmware** (no patched bionic/vendor images).

## Lineage

This fork is built in layers:

1. **Original libhybris** (Carsten Munk) -- core infrastructure for loading bionic-linked Android `.so` files from glibc programs: linker, hooks, EGL/GLES/Vulkan wrappers, gralloc.
2. **Droidian** -- Android 12+ support: VNDK version control, APEX/`system_ext` library paths, HWC2 HIDL/AIDL compatibility layers. Commits prefixed `q:`.
3. **Lindroid** -- app-based HWC2 composer (`vendor.lindroid.composer` AIDL service), CI infrastructure, additional Android 14 fixes. The `compat/apphwc/` directory is Lindroid's.
4. **tawc additions** -- see below.

## What's unique to this fork

Two commits on top of Lindroid's work, solving TLS compatibility on stock (unpatched) Android 16:

- **`b6e3de9` -- TLS thunk patcher** (originated in lindroid-drm, by Nikita Ukhrenkov). Patches `mrs TPIDR_EL0` + `ldr` instruction sequences at runtime to redirect hardcoded bionic TLS slot accesses to safe locations. Enabled with `HYBRIS_PATCH_TLS=1`. Without this, GPU drivers crash on TLS access.

- **`9517311` -- bionic_tls compat for stock firmware**. Stock bionic reads `TLS_SLOT_BIONIC_TLS` (slot -1), expecting a ~12KB `bionic_tls` struct. This commit restructures the TLS hook array and lazy-allocates the struct per-thread (via wrapped `pthread_create`). This is the change that makes stock firmware work without patched vendor images.

Together these give us working EGL 1.5 on Pixel 4a (Adreno 618) running stock LineageOS Android 16.

## Build

Built via the tawc project (not scripts in this repo):

```
# from the tawc repo root:
bash client/build-libhybris [--clean]
```

Syncs local `./libhybris` to the phone and builds inside the Arch chroot. See `client/build-libhybris` in the tawc repo for details.
