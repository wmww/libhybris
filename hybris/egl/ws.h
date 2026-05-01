/*
 * Copyright (c) 2013-2022 Jolla Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __LIBHYBRIS_WS_H
#define __LIBHYBRIS_WS_H
#include <EGL/egl.h>
#include <EGL/eglext.h>

struct ws_egl_interface {
	void * (*android_egl_dlsym)(const char *symbol);

	int (*has_mapping)(EGLSurface surface);
	EGLNativeWindowType (*get_mapping)(EGLSurface surface);
};

/* Defined in egl.c */
extern struct ws_egl_interface hybris_egl_interface;

struct _EGLDisplay {
	EGLDisplay dpy;
};

struct egl_image
{
	EGLImageKHR egl_image;
	EGLenum target;
	struct _EGLDisplay *ws_dpy;
	EGLClientBuffer ws_buffer;
};

struct ws_module {
	void (*init_module)(struct ws_egl_interface *egl_interface);

	struct _EGLDisplay *(*GetDisplay)(EGLNativeDisplayType native);
	void (*Terminate)(struct _EGLDisplay *display);
	EGLNativeWindowType (*CreateWindow)(EGLNativeWindowType win, struct _EGLDisplay *display);
	void (*DestroyWindow)(EGLNativeWindowType win);
	__eglMustCastToProperFunctionPointerType (*eglGetProcAddress)(const char *procname);
	void (*passthroughImageKHR)(EGLContext *ctx, EGLenum *target, EGLClientBuffer *buffer, const EGLint **attrib_list);
	const char *(*eglQueryString)(EGLDisplay dpy, EGLint name, const char *(*real_eglQueryString)(EGLDisplay dpy, EGLint name));
	void (*prepareSwap)(EGLDisplay dpy, EGLNativeWindowType win, EGLint *damage_rects, EGLint damage_n_rects);
	void (*finishSwap)(EGLDisplay dpy, EGLNativeWindowType win);
	void (*setSwapInterval)(EGLDisplay dpy, EGLNativeWindowType win, EGLint interval);
	void (*releaseDisplay)(struct _EGLDisplay *dpy);
	void (*eglInitialized)(struct _EGLDisplay *dpy);
	/* Optional. Lets a platform plugin override the value returned for
	 * a given EGLConfig attribute. The X11 plugin uses this to substitute
	 * a real X11 visual ID for EGL_NATIVE_VISUAL_ID — Android EGL returns
	 * the HAL pixel format there, which is meaningless to X11 clients
	 * (XGetVisualInfo with that ID returns NULL → es2gears_x11/glmark2/etc
	 * fail "Could not get a valid XVisualInfo").
	 *
	 * Returns EGL_TRUE if handled (the value in *out_value is final),
	 * EGL_FALSE to fall through to Android EGL. */
	EGLBoolean (*eglGetConfigAttrib)(struct _EGLDisplay *dpy, EGLConfig config,
	                                 EGLint attribute, EGLint *out_value);
};

EGLBoolean ws_init(const char * egl_platform);
void ws_eglInitialized(struct _EGLDisplay *dpy);

struct _EGLDisplay *ws_GetDisplay(EGLNativeDisplayType native);
void ws_Terminate(struct _EGLDisplay *dpy);
EGLNativeWindowType ws_CreateWindow(EGLNativeWindowType win, struct _EGLDisplay *display);
void ws_DestroyWindow(EGLNativeWindowType win);
__eglMustCastToProperFunctionPointerType ws_eglGetProcAddress(const char *procname);
void ws_passthroughImageKHR(EGLContext *ctx, EGLenum *target, EGLClientBuffer *buffer, const EGLint **attrib_list);
const char *ws_eglQueryString(EGLDisplay dpy, EGLint name, const char *(*real_eglQueryString)(EGLDisplay dpy, EGLint name));
void ws_prepareSwap(EGLDisplay dpy, EGLNativeWindowType win, EGLint *damage_rects, EGLint damage_n_rects);
void ws_finishSwap(EGLDisplay dpy, EGLNativeWindowType win);
void ws_setSwapInterval(EGLDisplay dpy, EGLNativeWindowType win, EGLint interval);
void ws_releaseDisplay(struct _EGLDisplay *dpy);
EGLBoolean ws_eglGetConfigAttrib(struct _EGLDisplay *dpy, EGLConfig config,
                                 EGLint attribute, EGLint *out_value);

#endif
