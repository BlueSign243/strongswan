AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	$(PQMAGIC_CFLAGS)

AM_CFLAGS = $(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-pqmagic.la
else
plugin_LTLIBRARIES = libstrongswan-pqmagic.la
endif

libstrongswan_pqmagic_la_SOURCES = \
	pqmagic_plugin.c pqmagic_plugin.h pqmagic_kem.c pqmagic_kem.h

libstrongswan_pqmagic_la_LDFLAGS = -module -avoid-version
libstrongswan_pqmagic_la_LIBADD = $(PQMAGIC_LIBS)

if USE_PQMAGIC_SIGN
libstrongswan_pqmagic_la_SOURCES += \
    pqmagic_sig_params.h pqmagic_aigis_sig.c pqmagic_aigis_sig.h \
    pqmagic_composite_sig.c pqmagic_composite_sig.h \
    pqmagic_sig_encoding.c pqmagic_sig_encoding.h
endif
