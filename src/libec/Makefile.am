# This file is part of libec (https://github.com/erayd/libec/).
# Copyright (C) 2014 Erayd LTD. All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   * Neither the name of Erayd LTD nor the
#     names of its contributors may be used to endorse or promote products
#     derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL ERAYD LTD BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

if DEBUG
AM_CFLAGS = -std=gnu99 -Wall -Werror -Wno-parentheses -ggdb
else !DEBUG
AM_CFLAGS = -Wall -Wno-parentheses -std=gnu99 -g -O2
endif !DEBUG

include_HEADERS = ec.h

lib_LTLIBRARIES = libec.la

libec_la_LDFLAGS = -version-info 0:0:0 -lsodium
libec_la_CFLAGS = $(AM_CFLAGS) -DTARGET_LIBEC
libec_la_SOURCES = common.h \
		      config.h \
                      ec.h \
                      libec.c \
                      cert.c \
                      error.c \
                      export.c \
                      record.c \
                      role.c
