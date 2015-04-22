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

/**
 * Save a certificate in the local store
 */
ec_err_t ec_store_save(ec_ctx_t ctx, ec_cert_t *c) {
  assert(ctx->save, EC_EUNDEFINED, NULL);
  return ctx->save(c);
}

/**
 * Load a certificate from the local store
 */
ec_cert_t *ec_store_load(ec_ctx_t ctx, ec_id_t id) {
  assert(ctx->load, EC_EUNDEFINED, NULL);
  return ctx->load(id);
}

/**
 * Remove a certificate from the local store
 */
ec_err_t ec_store_remove(ec_ctx_t ctx, ec_id_t id) {
  assert(ctx->remove, EC_EUNDEFINED, NULL);
  return ctx->remove(id);
}
