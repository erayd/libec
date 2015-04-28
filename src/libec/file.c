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

#include <common.h>
#include <stdio.h>

/**
 * Put the contents of a buffer into a file
 */
ec_err_t ec_file_put(char *path, unsigned char *buf, size_t length) {
  FILE *fp = fopen(path, "w");
  if(!fp)
    return EC_EFILE;
  size_t i = 0;
  for(; i < length; i += fwrite(&buf[i], 1, length - i, fp));
  fclose(fp);
  if(i < length)
    return EC_EFILE;
  return EC_OK;
}

/**
 * Get the contents of a file into a malloc()d buffer
 */
ec_err_t ec_file_get(unsigned char **buf, size_t *length, char *path) {
  FILE *fp = fopen(path, "r");
  if(!fp || fseek(fp, 0, SEEK_END))
    return EC_EFILE;
  *length = ftell(fp);
  rewind(fp);
  if(*length == 0)
    return EC_EEMPTY;
  else if(*length < 0)
    return EC_EFILE;
  ec_abort(*buf = malloc(*length), EC_ENOMEM, NULL);
  size_t i = 0;
  for(; i < *length; i += fread(&(*buf)[i], 1, *length - i, fp));
  if(i < *length) {
    free(*buf);
    return EC_EFILE;
  }
  return EC_OK;
}
