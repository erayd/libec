#!/bin/sh
# 
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
