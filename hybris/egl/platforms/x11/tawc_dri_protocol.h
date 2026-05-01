/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Wire definitions for tawc's TAWC-DRI X11 extension. This must match
 * Xext/tawcdriproto.h shipped with our Xwayland fork
 * (xwayland-patches/xwayland/02-tawc-step3-ahb-present.patch).
 *
 * We don't generate XCB stubs from xcbproto; the protocol is small and
 * lives in two places (server and this one client). Hand-rolled.
 */

#ifndef LIBHYBRIS_X11_TAWC_DRI_PROTOCOL_H
#define LIBHYBRIS_X11_TAWC_DRI_PROTOCOL_H

#include <stdint.h>

#define TAWC_DRI_NAME              "TAWC-DRI"
#define TAWC_DRI_MAJOR             0
#define TAWC_DRI_MINOR             2

#define X_TAWCDRI_QueryVersion     0
#define X_TAWCDRI_PresentBuffer    1

typedef struct {
    uint8_t  major_opcode;
    uint8_t  minor_opcode;
    uint16_t length;
    uint32_t major_version;
    uint32_t minor_version;
} tawc_dri_query_version_req;

typedef struct {
    uint8_t  response_type;
    uint8_t  pad0;
    uint16_t sequence;
    uint32_t length;
    uint32_t major_version;
    uint32_t minor_version;
    uint32_t pad1[5];
} tawc_dri_query_version_reply;

typedef struct __attribute__((packed)) {
    uint8_t  major_opcode;
    uint8_t  minor_opcode;
    uint16_t length;
    uint32_t window;
    uint16_t num_fds;
    uint16_t num_ints;
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    uint32_t format;
    uint32_t usage_lo;
    uint32_t usage_hi;
} tawc_dri_present_buffer_req;

#endif
