#
# This file is part of libec (https://github.com/erayd/libec/).
# Copyright (C) 2014-2015, Erayd LTD
#
# Permission to use, copy, modify, and/or distribute this software for any purpose
# with or without fee is hereby granted, provided that the above copyright notice
# and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT,
# OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
# DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

SUBDIRS = . tests

if DEBUG
AM_CFLAGS = -std=c99 -pedantic -Wall -Werror -Wno-parentheses -ggdb
else !DEBUG
AM_CFLAGS = -Wall -Wno-parentheses -std=c99 -pedantic -g -O2
endif !DEBUG

include_HEADERS = include/ec.h

lib_LTLIBRARIES = libec.la

libec_la_LDFLAGS = -version-info @EC_LIBTOOL_VERSION@
libec_la_CFLAGS = $(AM_CFLAGS) -DTARGET_LIBEC
libec_la_SOURCES = ../config.h \
		   include/common.h \
                   include/ec.h \
                   libec.c \
                   misc/base64.c \
                   misc/context.c \
                   misc/error.c \
                   misc/skiplist.c \
                   cert/cert.c \
                   cert/export.c \
                   cert/record.c \
                   cert/role.c \
                   channel/channel.c
