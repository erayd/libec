/*
This file is part of libec (https://github.com/erayd/libec/).
Copyright (C) 2014-2015, Erayd LTD

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT,
OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#include <include/common.h>
#include <stdarg.h>

/**
 * Free pointers if malloc fails
 */
void *fmalloc_real(size_t size, void *canary, ...) {
  void *p = malloc(size);
  if(!p) {
    va_list ap;
    va_start(ap, canary);
    for(void *fp = va_arg(ap, void*); fp != canary; fp = va_arg(ap, void*)) {
      if(fp)
        free(fp);
    }
    va_end(ap);
  }
  return p;
}

/**
 * Free pointers if calloc fails
 */
void *fcalloc_real(size_t size, void *canary, ...) {
  void *p = calloc(1, size);
  if(!p) {
    va_list ap;
    va_start(ap, canary);
    for(void *fp = va_arg(ap, void*); fp != canary; fp = va_arg(ap, void*)) {
      if(fp)
        free(fp);
    }
    va_end(ap);
  }
  return p;
}
