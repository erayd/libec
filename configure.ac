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

AC_PREREQ([2.68])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/libec/libec.c])
AC_INIT([libec], [0.2.0-dev], [steve@erayd.net], [libec], [https://github.com/erayd/libec/])
LT_INIT
AM_INIT_AUTOMAKE([1.11 dist-bzip2 tar-ustar foreign subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Features
AC_ARG_ENABLE([debug], AS_HELP_STRING([--enable-debug], [Enable debugging]), [], [enable_debug=no])
AS_IF([test "x$enable_debug" != xno], [
  AC_DEFINE(DEBUG, 1, [Define this to enable additional debugging features. Not for production builds.])
  AM_CONDITIONAL(DEBUG, true)
], [
  AM_CONDITIONAL(DEBUG, false)
])

AC_ARG_ENABLE([pa], AS_HELP_STRING([--enable-pa], [Enable debug output for passing assertions]), [], [enable_pa=no])
AS_IF([test "x$enable_pa" != xno], [
  AC_DEFINE(DEBUG_PA, 1, [Define this to enable debug output for passing assertions. Not for production builds.])
  AM_CONDITIONAL(DEBUG_PA, true)
], [
  AM_CONDITIONAL(DEBUG_PA, false)
])

# Checks for pkgconfig modules
PKG_CHECK_MODULES([SODIUM], [libsodium >= 1.0.0] , , [AC_MSG_ERROR([libsodium must be at least v1.0.0!])])
PKG_CHECK_MODULES([TALLOC], [talloc >= 2.0.0] , , [AC_MSG_ERROR([talloc must be at least v2.0.0!])])

# Checks for programs.
AC_PROG_LIBTOOL
AM_PROG_LIBTOOL
AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB([sodium], [main], [], [AC_MSG_ERROR([libsodium is missing!])])
AC_CHECK_LIB([talloc], [main], [], [AC_MSG_ERROR([libtalloc is missing!])])

# Checks for header files.
AC_CHECK_HEADER([sodium.h], [], [AC_MSG_ERROR([sodium.h is missing!])])
AC_CHECK_HEADER([talloc.h], [], [AC_MSG_ERROR([talloc.h is missing!])])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AM_CONFIG_HEADER([src/config.h])
AC_OUTPUT(Makefile src/Makefile src/libec/Makefile src/libec/tests/Makefile)
