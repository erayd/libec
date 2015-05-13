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

AM_CFLAGS = -std=gnu99 -Wall -Werror -Wno-parentheses -ggdb

TESTS_TARGETS = cert \
		ctx \
		cert_chain \
		role \
		export \
		channel

check_PROGRAMS = $(TESTS_TARGETS)

TESTS = $(TESTS_TARGETS)

TESTS_SOURCES = ${top_builddir}/src/libec/include/ec.h tests.h
TESTS_LDADD = ../libec.la

cert_SOURCES = $(TESTS_SOURCES) test_cert.c
cert_LDADD = $(TESTS_LDADD)

ctx_SOURCES = $(TESTS_SOURCES) test_ctx.c
ctx_LDADD = $(TESTS_LDADD)

cert_chain_SOURCES = $(TESTS_SOURCES) test_cert_chain.c
cert_chain_LDADD = $(TESTS_LDADD)

role_SOURCES = $(TESTS_SOURCES) test_role.c
role_LDADD = $(TESTS_LDADD)

export_SOURCES = $(TESTS_SOURCES) test_export.c
export_LDADD = $(TESTS_LDADD)

channel_SOURCES = $(TESTS_SOURCES) test_channel.c
channel_LDADD = $(TESTS_LDADD)
