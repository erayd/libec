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

AC_PREREQ([2.68])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/libec/ec.h])
AC_INIT([libec], [0.1.0-dev], [steve@erayd.net], [libec], [https://github.com/erayd/libec/])
LT_INIT
AM_INIT_AUTOMAKE

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

# Checks for programs.
AC_PROG_LIBTOOL
AM_PROG_LIBTOOL
AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB([sodium], [main], [], [AC_MSG_ERROR([libsodium is missing!])])

# Checks for header files.
AC_CHECK_HEADER([sodium.h], [], [AC_MSG_ERROR([sodium.h is missing!])])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AM_CONFIG_HEADER([src/config.h])
AC_OUTPUT(Makefile src/Makefile src/libec/Makefile)
