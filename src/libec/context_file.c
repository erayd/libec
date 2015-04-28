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
#include <string.h>
#include <malloc.h>
#include <unistd.h>

/**
 * Return a malloc()d string with the full id path in the store
 */
static char *idpath(char *path, ec_id_t id) {
  char *idpath = calloc(1, strlent(path) + ec_base64_len(sizeof(ec_id_t)) + 1);
  ec_abort(idpath, EC_ENOMEM, NULL);
  strcat(idpath, path);
  if(idpath[strlen(idpath) - 1] != '/')
    strcat(idpath, "/");
  ec_base64_encode(&idpath[strlen(idpath)], id, sizeof(ec_id_t));
  return idpath;
}

ec_err_t ec_ctx_file_init(char *location) {
  return EC_ENOTIMPLEMENTED;
}

/**
 * Save a certificate to a file in the store
 */
ec_err_t ec_ctx_file_save(ec_ctx_t ctx, ec_cert_t *c) {
  ec_id_t id;
  ec_cert_id(id, c);
  char *path = idpath(ctx->location, id);
  
  unsigned char packed[ec_export_len(c, EC_EXPORT_TRUSTED)];
  ec_export(packed, c, EC_EXPORT_TRUSTED);

  ec_err_t result = ec_file_put(path, packed, sizeof(packed));
  free(path);
  return result;
}

/**
 * Load a certificate file from the store
 */
ec_cert_t *ec_ctx_file_load(ec_ctx_t ctx, ec_id_t id) {
  char *path = idpath(ctx->location, id);
  unsigned char *buf;
  size_t length;
  ec_cert_t *c;
  ec_err_t result = ec_file_get(&buf, &length, path);
  if(!result)
    c = ec_import(buf, length, 0);
  free(buf);
  free(path);
  return (result || !c) ? NULL : c;
}

/**
 * Delete a certificate file from the store
 */
ec_err_t ec_ctx_file_remove(ec_ctx_t ctx, ec_id_t id) {
  char *path = idpath(ctx->location, id);
  int result = unlink(path);
  free(path);
  return result ? EC_EFILE : EC_OK;
}
