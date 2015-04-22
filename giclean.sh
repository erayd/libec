#!/bin/sh
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

# Looks for a .gitignore file in the current working directory, and recursively deletes all
# files and folders referenced in that file. Note that .gitignore files in subdirectories
# are not processed.

WDIR="$1"
[ -z "$WDIR" ] && WDIR=.
[ -e "$WDIR/.gitignore" ] || (echo .gitignore is missing! && exit 1)
cat "$WDIR/.gitignore" | while read PATTERN; do
  if [ "${PATTERN:0:1}" == "/" ]; then
    find "$WDIR" -depth -wholename "$WDIR/${PATTERN:1}" -printf '%P\n' | grep -ve '^\([^/]+/\)*\.git\(/.*\)\?$' | xargs -n 1 -rd \\n rm -rfv
  else
    find "$WDIR" -depth -name "$PATTERN" -printf '%P\n' | grep -ve '^\([^/]+/\)*\.git\(/.*\)\?$' | xargs -n 1 -rd \\n rm -rfv
  fi
done
