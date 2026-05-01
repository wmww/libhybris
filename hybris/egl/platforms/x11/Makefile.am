pkglib_LTLIBRARIES = eglplatform_x11.la

eglplatform_x11_la_SOURCES = eglplatform_x11.cpp x11_window.cpp
eglplatform_x11_la_CXXFLAGS = \
	-I$(top_srcdir)/common \
	-I$(top_srcdir)/platforms/common \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/egl \
	-I$(top_srcdir)/egl/platforms/common \
	-I$(top_builddir)/egl/platforms/common \
	$(ANDROID_HEADERS_CFLAGS) \
	$(X11_CFLAGS) \
	$(XCB_CFLAGS) \
	$(X11_XCB_CFLAGS)

if WANT_DEBUG
eglplatform_x11_la_CXXFLAGS += -ggdb -O0
endif

if WANT_TRACE
eglplatform_x11_la_CXXFLAGS += -DDEBUG
endif

eglplatform_x11_la_LDFLAGS = \
	-avoid-version -module -shared -export-dynamic \
	$(top_builddir)/platforms/common/libhybris-platformcommon.la \
	$(top_builddir)/egl/platforms/common/libhybris-eglplatformcommon.la \
	$(top_builddir)/gralloc/libgralloc.la \
	$(X11_LIBS) \
	$(XCB_LIBS) \
	$(X11_XCB_LIBS)

if HAS_ANDROID_4_2_0
eglplatform_x11_la_LDFLAGS += $(top_builddir)/libsync/libsync.la
endif

if HAS_ANDROID_5_0_0
eglplatform_x11_la_LDFLAGS += $(top_builddir)/libsync/libsync.la
endif
