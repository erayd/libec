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
#include <string.h>


/**
 * Lookup char in the table
 */
static unsigned char _table(char c) {
  const char *table = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
  char *d = (char*)table;
  for(; *d; d++) {
    if(c == *d)
      return d - table;
  }
  return 0;
}

/**
 * Get the base64-encoded length for a buffer
 */
size_t ec_base64_len(size_t length) {
  return (length / 3 + !!(length % 3)) * 4;
}

/**
 * Encode src as base64 into dest
 */
size_t ec_base64_encode(char *dest, unsigned char *src, size_t length) {
  const char *table = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
  char *pos = dest;
  while(length) {
    *pos++ = table[0x3F & (src[0] >> 2)];
    if(length >= 3) {
      *pos++ = table[0x3F & (src[0] << 4) | 0x3F & (src[1] >> 4)];
      *pos++ = table[0x3F & (src[1] << 2) | 0x3F & (src[2] >> 6)];
      *pos++ = table[0x3F & src[2]];
      length -= 3;
      src += 3;
      continue;
    }
    if(length == 2) {
      *pos++ = table[0x3F & (src[0] << 4) | 0x3F & (src[1] >> 4)];
      *pos++ = table[0x3F & (src[1] << 2)];
      *pos++ = '=';
    }
    else {
      *pos++ = table[0x3F & (src[0] << 4)];
      *pos++ = '=';
      *pos++ = '=';
    }
    break;
  }
  return pos - dest;
}

/**
 * Decode base64 src into dest
 */
size_t ec_base64_decode(unsigned char *dest, char *src, size_t length) {
  unsigned char *pos = dest;
  while(length >= 4) {
    *pos++ = _table(src[0]) << 2 | _table(src[1]) >> 4;
    if(src[2] != '=') {
      *pos++ = _table(src[1]) << 4 | _table(src[2]) >> 2;
      if(src[3] != '=')
        *pos++ = _table(src[2]) << 6 | _table(src[3]);
    }
    src += 4;
    length -= 4;
  }
  return pos - dest;
}
