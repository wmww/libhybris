/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * libhybris EGL-on-X11 platform plugin.
 *
 * Implements ws_module so chroot-side glibc clients can call
 *   eglGetPlatformDisplay(EGL_PLATFORM_X11_KHR, dpy, NULL)
 * and get a working EGL display backed by the Android vendor GLES via
 * libhybris. eglSwapBuffers ships AHardwareBuffers from the client to
 * the X server (Xwayland with the tawc patches) over the existing X11
 * connection via the TAWC-DRI extension; the server then forwards
 * them to the tawc compositor through android_wlegl. End-to-end zero
 * CPU-readback for pure GL-X11 clients.
 *
 * See notes/xwayland.md (Phase 2 step 4).
 */

#include <android-config.h>
#include <ws.h>
#include <eglhybris.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include <eglplatformcommon.h>
}

#include <EGL/eglext.h>

extern "C" {
#include <X11/Xlib.h>
#include <X11/Xlib-xcb.h>
#include <xcb/xcb.h>
}

#include <hybris/gralloc/gralloc.h>
#include "x11_window.h"
#include "tawc_dri_protocol.h"
#include "logging.h"

struct X11Display {
    _EGLDisplay base;
    Display *xdpy;
    bool owns_xdpy;
    xcb_connection_t *conn;
    int init_count;
    uint8_t tawc_dri_opcode;
    bool tawc_dri_present;
    /* Cached at GetDisplay so eglGetConfigAttrib(EGL_NATIVE_VISUAL_ID)
     * can return immediately. The screen's default visual is a 32-bit
     * TrueColor on every modern X server (Xwayland included), which
     * matches the RGBA8888 EGLConfig clients ask for. */
    uint32_t default_visual_id;
};

extern "C" void x11ws_init_module(struct ws_egl_interface *egl_iface)
{
    hybris_gralloc_initialize(0);
    eglplatformcommon_init(egl_iface);
}

extern "C" _EGLDisplay *x11ws_GetDisplay(EGLNativeDisplayType display)
{
    X11Display *xdisp = new X11Display();
    xdisp->xdpy = (Display *)display;
    xdisp->owns_xdpy = false;
    xdisp->conn = NULL;
    xdisp->init_count = 0;
    xdisp->tawc_dri_opcode = 0;
    xdisp->tawc_dri_present = false;

    if (!xdisp->xdpy) {
        xdisp->xdpy = XOpenDisplay(NULL);
        if (!xdisp->xdpy) {
            HYBRIS_ERROR("x11-platform: XOpenDisplay(NULL) failed (DISPLAY=%s)",
                         getenv("DISPLAY"));
            delete xdisp;
            return NULL;
        }
        xdisp->owns_xdpy = true;
    }
    xdisp->conn = XGetXCBConnection(xdisp->xdpy);
    if (!xdisp->conn) {
        HYBRIS_ERROR("x11-platform: XGetXCBConnection returned NULL");
        if (xdisp->owns_xdpy) XCloseDisplay(xdisp->xdpy);
        delete xdisp;
        return NULL;
    }
    int scr = DefaultScreen(xdisp->xdpy);
    xdisp->default_visual_id =
        (uint32_t)XVisualIDFromVisual(DefaultVisual(xdisp->xdpy, scr));
    return &xdisp->base;
}

extern "C" EGLBoolean x11ws_eglGetConfigAttrib(_EGLDisplay *dpy,
                                               EGLConfig /*config*/,
                                               EGLint attribute,
                                               EGLint *out_value)
{
    if (attribute != EGL_NATIVE_VISUAL_ID)
        return EGL_FALSE;
    X11Display *xdisp = (X11Display *)dpy;
    if (!xdisp || !xdisp->default_visual_id)
        return EGL_FALSE;
    *out_value = (EGLint)xdisp->default_visual_id;
    return EGL_TRUE;
}

extern "C" void x11ws_releaseDisplay(_EGLDisplay *dpy)
{
    X11Display *xdisp = (X11Display *)dpy;
    if (xdisp->owns_xdpy && xdisp->xdpy)
        XCloseDisplay(xdisp->xdpy);
    delete xdisp;
}

extern "C" void x11ws_eglInitialized(_EGLDisplay *dpy)
{
    X11Display *xdisp = (X11Display *)dpy;
    if (xdisp->init_count++ > 0)
        return;

    /* Probe TAWC-DRI: QueryExtension to get the major opcode, then
     * QueryVersion to confirm the server speaks our wire shape. */
    xcb_query_extension_cookie_t qe_c =
        xcb_query_extension(xdisp->conn,
                            (uint16_t)strlen(TAWC_DRI_NAME),
                            TAWC_DRI_NAME);
    xcb_query_extension_reply_t *qe =
        xcb_query_extension_reply(xdisp->conn, qe_c, NULL);
    if (!qe || !qe->present) {
        HYBRIS_ERROR("x11-platform: TAWC-DRI extension not advertised by "
                     "the X server. The libhybris X11 EGL platform requires "
                     "a tawc-patched Xwayland (see notes/xwayland.md).");
        free(qe);
        return;
    }
    xdisp->tawc_dri_opcode = qe->major_opcode;
    xdisp->tawc_dri_present = true;
    free(qe);
}

extern "C" void x11ws_Terminate(_EGLDisplay *dpy)
{
    X11Display *xdisp = (X11Display *)dpy;
    if (xdisp->init_count > 0)
        --xdisp->init_count;
}

extern "C" EGLNativeWindowType x11ws_CreateWindow(EGLNativeWindowType win,
                                                  _EGLDisplay *display)
{
    X11Display *xdisp = (X11Display *)display;
    if (!xdisp->tawc_dri_present) {
        HYBRIS_ERROR("x11-platform: cannot create window — TAWC-DRI not "
                     "available on this X server.");
        return NULL;
    }

    /* EGLNativeWindowType for X11 is an Xlib `Window` (a 32-bit XID).
     * The standard EGL X11 platform doesn't expose width/height in the
     * native-window-type — we have to GetGeometry. */
    xcb_window_t xwin = (xcb_window_t)(uintptr_t)win;
    xcb_get_geometry_reply_t *gg =
        xcb_get_geometry_reply(xdisp->conn,
                               xcb_get_geometry(xdisp->conn, xwin), NULL);
    if (!gg) {
        HYBRIS_ERROR("x11-platform: GetGeometry on window 0x%x failed", xwin);
        return NULL;
    }
    unsigned int w = gg->width  ? gg->width  : 1;
    unsigned int h = gg->height ? gg->height : 1;
    free(gg);

    X11NativeWindow *window =
        new X11NativeWindow(xdisp->conn, xwin, xdisp->tawc_dri_opcode, w, h);
    window->common.incRef(&window->common);
    return (EGLNativeWindowType)static_cast<ANativeWindow *>(window);
}

extern "C" void x11ws_DestroyWindow(EGLNativeWindowType win)
{
    X11NativeWindow *window =
        static_cast<X11NativeWindow *>((ANativeWindow *)win);
    window->common.decRef(&window->common);
}

extern "C" __eglMustCastToProperFunctionPointerType
x11ws_eglGetProcAddress(const char *procname)
{
    return eglplatformcommon_eglGetProcAddress(procname);
}

extern "C" void x11ws_passthroughImageKHR(EGLContext *ctx, EGLenum *target,
                                          EGLClientBuffer *buffer,
                                          const EGLint **attrib_list)
{
    eglplatformcommon_passthroughImageKHR(ctx, target, buffer, attrib_list);
}

extern "C" const char *x11ws_eglQueryString(EGLDisplay dpy, EGLint name,
        const char *(*real_eglQueryString)(EGLDisplay dpy, EGLint name))
{
    return eglplatformcommon_eglQueryString(dpy, name, real_eglQueryString);
}

extern "C" void x11ws_prepareSwap(EGLDisplay, EGLNativeWindowType win,
                                  EGLint *damage_rects, EGLint damage_n_rects)
{
    X11NativeWindow *window =
        static_cast<X11NativeWindow *>((ANativeWindow *)win);
    window->prepareSwap(damage_rects, damage_n_rects);
}

extern "C" void x11ws_finishSwap(EGLDisplay, EGLNativeWindowType win)
{
    X11NativeWindow *window =
        static_cast<X11NativeWindow *>((ANativeWindow *)win);
    window->finishSwap();
}

extern "C" void x11ws_setSwapInterval(EGLDisplay, EGLNativeWindowType win,
                                      EGLint interval)
{
    X11NativeWindow *window =
        static_cast<X11NativeWindow *>((ANativeWindow *)win);
    window->setSwapInterval(interval);
}

struct ws_module ws_module_info = {
    x11ws_init_module,
    x11ws_GetDisplay,
    x11ws_Terminate,
    x11ws_CreateWindow,
    x11ws_DestroyWindow,
    x11ws_eglGetProcAddress,
    x11ws_passthroughImageKHR,
    x11ws_eglQueryString,
    x11ws_prepareSwap,
    x11ws_finishSwap,
    x11ws_setSwapInterval,
    x11ws_releaseDisplay,
    x11ws_eglInitialized,
    x11ws_eglGetConfigAttrib,
};
