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

if DEBUG
AM_CFLAGS = -std=gnu99 -Wall -Werror -Wno-parentheses -ggdb
else !DEBUG
AM_CFLAGS = -Wall -Wno-parentheses -std=gnu99 -g -O2
endif !DEBUG

include_HEADERS = ec.h

lib_LTLIBRARIES = libec.la

noinst_PROGRAMS = test

libec_la_LDFLAGS = -version-info 0:0:0 -lsodium
libec_la_CFLAGS = $(AM_CFLAGS) -DTARGET_LIBEC
libec_la_SOURCES = common.h \
		      config.h \
                      ec.h \
                      libec.c \
                      base64.c \
                      cert.c \
                      context.c \
                      error.c \
                      export.c \
                      record.c \
                      role.c

test_LDFLAGS = -lec
test_CFLAGS = $(AM_CFLAGS) -DTARGET_TEST
test_SOURCES = test.c ec.h
