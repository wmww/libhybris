/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <android-config.h>
#include <hardware/gralloc.h>
#include "x11_window.h"
#include "tawc_dri_protocol.h"
#include "logging.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#if ANDROID_VERSION_MAJOR>=4 && ANDROID_VERSION_MINOR>=2 || ANDROID_VERSION_MAJOR>=5
extern "C" {
#include <sync/sync.h>
}
#endif

extern "C" {
#include <xcb/xcbext.h>
}

X11NativeWindowBuffer::X11NativeWindowBuffer(unsigned int w,
                                             unsigned int h,
                                             unsigned int fmt,
                                             uint64_t usg)
    : busy(0)
    , youngest(0)
{
    ANativeWindowBuffer::width  = w;
    ANativeWindowBuffer::height = h;
    ANativeWindowBuffer::format = fmt;
    ANativeWindowBuffer::usage  = usg;
    int rc = hybris_gralloc_allocate(w ? w : 1,
                                     h ? h : 1,
                                     fmt, (uint32_t)usg,
                                     &this->handle, (uint32_t *)&this->stride);
    assert(rc == 0);
    this->common.incRef(&this->common);
}

X11NativeWindowBuffer::~X11NativeWindowBuffer()
{
    if (this->handle)
        hybris_gralloc_release(this->handle, 1);
}

X11NativeWindow::X11NativeWindow(xcb_connection_t *conn,
                                 xcb_window_t xwin,
                                 uint8_t tawc_dri_opcode,
                                 unsigned int w,
                                 unsigned int h)
    : m_conn(conn)
    , m_xwin(xwin)
    , m_tawc_dri_opcode(tawc_dri_opcode)
    , m_width(w ? w : 1)
    , m_height(h ? h : 1)
    , m_format(HAL_PIXEL_FORMAT_RGBA_8888)
    , m_usage(GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_TEXTURE)
    , m_swap_interval(1)
    , m_freeBufs(0)
{
    const_cast<int &>(ANativeWindow::minSwapInterval) = 0;
    const_cast<int &>(ANativeWindow::maxSwapInterval) = 1;
    pthread_mutex_init(&m_mutex, NULL);
    setBufferCount(3);
}

X11NativeWindow::~X11NativeWindow()
{
    destroyBuffers();
    pthread_mutex_destroy(&m_mutex);
}

void X11NativeWindow::lock()   { pthread_mutex_lock(&m_mutex); }
void X11NativeWindow::unlock() { pthread_mutex_unlock(&m_mutex); }

unsigned int X11NativeWindow::width()         const { return m_width;  }
unsigned int X11NativeWindow::height()        const { return m_height; }
unsigned int X11NativeWindow::format()        const { return m_format; }
unsigned int X11NativeWindow::defaultWidth()  const { return m_width;  }
unsigned int X11NativeWindow::defaultHeight() const { return m_height; }
unsigned int X11NativeWindow::queueLength()   const { return 1; }
unsigned int X11NativeWindow::transformHint() const { return 0; }
unsigned int X11NativeWindow::getUsage()      const { return m_usage; }

unsigned int X11NativeWindow::type() const
{
#if ANDROID_VERSION_MAJOR>=4 && ANDROID_VERSION_MINOR>=3 || ANDROID_VERSION_MAJOR>=5
    return NATIVE_WINDOW_SURFACE;
#else
    return NATIVE_WINDOW_SURFACE_TEXTURE_CLIENT;
#endif
}

int X11NativeWindow::setSwapInterval(int interval)
{
    if (interval < 0) interval = 0;
    if (interval > 1) interval = 1;
    lock();
    m_swap_interval = interval;
    unlock();
    return 0;
}

int X11NativeWindow::setBuffersFormat(int fmt)
{
    lock();
    if (fmt != m_format) {
        m_format = fmt;
        /* re-allocated lazily on next dequeue */
    }
    unlock();
    return NO_ERROR;
}

int X11NativeWindow::setBuffersDimensions(int w, int h)
{
    lock();
    if (m_width != w || m_height != h) {
        m_width = w;
        m_height = h;
    }
    unlock();
    return NO_ERROR;
}

void X11NativeWindow::resize(unsigned int w, unsigned int h)
{
    lock();
    m_width = w;
    m_height = h;
    unlock();
}

int X11NativeWindow::setUsage(uint64_t usg)
{
    usg |= GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_TEXTURE;
    lock();
    if (usg != m_usage) {
        m_usage = usg;
    }
    unlock();
    return NO_ERROR;
}

X11NativeWindowBuffer *X11NativeWindow::addBuffer()
{
    X11NativeWindowBuffer *wnb =
        new X11NativeWindowBuffer(m_width, m_height, m_format, m_usage);
    m_bufList.push_back(wnb);
    ++m_freeBufs;
    return wnb;
}

void X11NativeWindow::destroyBuffer(X11NativeWindowBuffer *wnb)
{
    if (!wnb) return;
    wnb->common.decRef(&wnb->common);
    --m_freeBufs;
}

void X11NativeWindow::destroyBuffers()
{
    for (auto *wnb : m_bufList)
        destroyBuffer(wnb);
    m_bufList.clear();
    m_queue.clear();
    m_freeBufs = 0;
}

int X11NativeWindow::setBufferCount(int cnt)
{
    if ((int)m_bufList.size() == cnt)
        return NO_ERROR;
    lock();
    if ((int)m_bufList.size() > cnt) {
        auto it = m_bufList.begin();
        for (int i = 0; i <= (int)m_bufList.size() - cnt; ++i) {
            destroyBuffer(*it);
            ++it;
            m_bufList.pop_front();
        }
    } else {
        for (int i = (int)m_bufList.size(); i < cnt; ++i)
            (void)addBuffer();
    }
    unlock();
    return NO_ERROR;
}

int X11NativeWindow::dequeueBuffer(BaseNativeWindowBuffer **buffer, int *fenceFd)
{
    lock();

    /* Pick a free, non-youngest buffer; fall back to any free one. */
    auto it = m_bufList.begin();
    for (; it != m_bufList.end(); ++it) {
        if ((*it)->busy) continue;
        if ((*it)->youngest) continue;
        break;
    }
    if (it == m_bufList.end()) {
        it = m_bufList.begin();
        for (; it != m_bufList.end() && (*it)->busy; ++it) {}
    }
    if (it == m_bufList.end()) {
        unlock();
        return NO_ERROR;
    }

    X11NativeWindowBuffer *wnb = *it;

    /* Re-allocate if dimensions/format changed since last use. */
    if ((unsigned)wnb->width  != (unsigned)m_width ||
        (unsigned)wnb->height != (unsigned)m_height ||
        (unsigned)wnb->format != (unsigned)m_format ||
        wnb->usage  != m_usage)
    {
        destroyBuffer(wnb);
        m_bufList.erase(it);
        wnb = addBuffer();
    }

    wnb->busy = 1;
    *buffer = wnb;
    if (fenceFd) *fenceFd = -1;
    --m_freeBufs;

    unlock();
    return NO_ERROR;
}

int X11NativeWindow::lockBuffer(BaseNativeWindowBuffer *)
{
    return NO_ERROR;
}

int X11NativeWindow::cancelBuffer(BaseNativeWindowBuffer *buffer, int fenceFd)
{
    X11NativeWindowBuffer *wnb = static_cast<X11NativeWindowBuffer *>(buffer);
    if (fenceFd >= 0) close(fenceFd);
    lock();
    wnb->busy = 0;
    ++m_freeBufs;
    for (auto *b : m_bufList) b->youngest = 0;
    wnb->youngest = 1;
    unlock();
    return 0;
}

void X11NativeWindow::prepareSwap(EGLint *, EGLint)
{
    /* TAWC-DRI doesn't carry damage rects today; the X server presents
     * full-buffer attaches. Hook reserved for parity with the wayland
     * platform when the protocol grows damage support. */
}

void X11NativeWindow::finishSwap()
{
    /* All work happens in queueBuffer (see comment in upstream
     * libhybris's wayland-egl: attach+commit inside queueBuffer so
     * drivers that skip eglSwapBuffers still submit). Nothing to do
     * here; the present already went out on the wire. */
}

/* Build a TAWCDRIPresentBuffer request and ship the fds out-of-band
 * via xcb_send_request_with_fds. xcb dups the fds and closes its
 * copies after sending — we keep the AHB-owned originals. */
int X11NativeWindow::presentBuffer(X11NativeWindowBuffer *wnb)
{
    const native_handle_t *nh = wnb->handle;
    if (!nh) {
        HYBRIS_ERROR("x11-platform: buffer has no native_handle");
        return -1;
    }
    int num_fds  = nh->numFds;
    int num_ints = nh->numInts;

    size_t hdr_sz  = sizeof(tawc_dri_present_buffer_req);
    size_t ints_sz = (size_t)num_ints * sizeof(int32_t);
    size_t body_sz = hdr_sz + ints_sz;
    /* xcb pads up via the ((body_sz + 3) / 4) length, so we pass
     * the unpadded body and let xcb handle alignment. */
    char body[body_sz > 256 ? 1 : 256];
    char *body_p = body_sz <= sizeof(body) ? body : (char *)malloc(body_sz);
    if (!body_p) return -1;

    tawc_dri_present_buffer_req hdr = {};
    hdr.length   = (uint16_t)((body_sz + 3) / 4);
    hdr.window   = (uint32_t)m_xwin;
    hdr.num_fds  = (uint16_t)num_fds;
    hdr.num_ints = (uint16_t)num_ints;
    hdr.width    = (uint32_t)wnb->width;
    hdr.height   = (uint32_t)wnb->height;
    hdr.stride   = (uint32_t)wnb->stride;
    hdr.format   = (uint32_t)wnb->format;
    hdr.usage_lo = (uint32_t)(wnb->usage & 0xffffffffULL);
    hdr.usage_hi = (uint32_t)((uint64_t)wnb->usage >> 32);
    memcpy(body_p, &hdr, hdr_sz);
    if (ints_sz > 0)
        memcpy(body_p + hdr_sz, nh->data + num_fds, ints_sz);

    struct iovec iov[3];
    iov[2].iov_base = body_p;
    iov[2].iov_len  = body_sz;

    int *xfds = NULL;
    if (num_fds > 0) {
        xfds = (int *)malloc(num_fds * sizeof(int));
        if (!xfds) {
            if (body_p != body) free(body_p);
            return -1;
        }
        for (int i = 0; i < num_fds; i++) {
            xfds[i] = dup(nh->data[i]);
            if (xfds[i] < 0) {
                while (--i >= 0) close(xfds[i]);
                free(xfds);
                if (body_p != body) free(body_p);
                return -1;
            }
        }
    }

    static xcb_extension_t tawc_dri_id = { TAWC_DRI_NAME, 0 };
    xcb_protocol_request_t pb_req = {};
    pb_req.count  = 1;
    pb_req.ext    = &tawc_dri_id;
    pb_req.opcode = X_TAWCDRI_PresentBuffer;
    pb_req.isvoid = 1;

    (void)xcb_send_request_with_fds(m_conn, 0, &iov[2], &pb_req,
                                    num_fds, xfds);
    free(xfds);
    xcb_flush(m_conn);
    if (body_p != body) free(body_p);
    return 0;
}

int X11NativeWindow::queueBuffer(BaseNativeWindowBuffer *buffer, int fenceFd)
{
    X11NativeWindowBuffer *wnb = static_cast<X11NativeWindowBuffer *>(buffer);

#if ANDROID_VERSION_MAJOR>=4 && ANDROID_VERSION_MINOR>=2 || ANDROID_VERSION_MAJOR>=5
    if (fenceFd >= 0) {
        sync_wait(fenceFd, -1);
        close(fenceFd);
    }
#endif

    lock();
    int rc = presentBuffer(wnb);

    /* No server→client release event in TAWC-DRI today. The 3-buffer
     * round-robin gives the compositor enough breathing room: by the
     * time we cycle back to a slot, the compositor has long since
     * released the wl_buffer the X server made for that frame. Mark
     * the buffer free immediately so dequeueBuffer can reuse it. */
    wnb->busy = 0;
    ++m_freeBufs;
    for (auto *b : m_bufList) b->youngest = 0;
    wnb->youngest = 1;
    unlock();
    return rc;
}
