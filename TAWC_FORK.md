# tawc libhybris fork

This fork is claudeslop: AI-written and AI-maintained as part of the [tawc](https://codeberg.org/sphi/tawc) project.

**Fork URL:** https://github.com/wmww/libhybris

## Purpose

Provide EGL/GLES access to Android GPU drivers from glibc programs running in a chroot, specifically for tawc's Wayland compositor. The key goal is running on **stock Android firmware** (no patched bionic/vendor images).

## Patches on top of upstream

Two commits on top of [upstream libhybris](https://github.com/libhybris/libhybris), solving TLS compatibility on stock (unpatched) Android:

- **TLS thunk patcher** (originated in lindroid-drm, by Nikita Ukhrenkov). Patches `mrs TPIDR_EL0` instruction sequences at runtime to redirect hardcoded bionic TLS slot accesses to safe locations. Always active on aarch64. Without this, GPU drivers segfault during EGL init -- confirmed required for both Adreno (Pixel 4a) and Mali (original motivation). Uses a two-pass approach (count MRS instructions, then allocate an exactly-sized thunk region) with fatal errors on any patching failure.

- **bionic_tls compat for stock firmware**. Stock bionic reads `TLS_SLOT_BIONIC_TLS` (slot -1), expecting a ~12KB `bionic_tls` struct. This commit restructures the TLS hook array and lazy-allocates the struct per-thread (via wrapped `pthread_create`). This is the change that makes stock firmware work without patched vendor images.

Together these give us working EGL 1.5 on Pixel 4a (Adreno 618) running stock LineageOS Android 16.

## Build

Built via the tawc project (not scripts in this repo):

```
# from the tawc repo root:
bash client/build-libhybris [--clean]
```

Syncs local `./libhybris` to the phone and builds inside the Arch chroot. See `client/build-libhybris` in the tawc repo for details.
