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
#include <malloc.h>

/**
 * Initialise a new context
 */
void ec_ctx_init(ec_ctx_t *ctx) {
  ec_assert(*ctx = calloc(1, sizeof(**ctx)), EC_ENOMEM, NULL);
}

/**
 * Destroy a context
 */
void ec_ctx_destroy(ec_ctx_t *ctx) {
  free(*ctx);
}

/**
 * Save a certificate in the local store
 */
ec_err_t ec_store_save(ec_ctx_t ctx, ec_cert_t *c) {
  ec_assert(ctx->save, EC_EUNDEFINED, NULL);
  return ctx->save(c);
}

/**
 * Load a certificate from the local store
 */
ec_cert_t *ec_store_load(ec_ctx_t ctx, ec_id_t id) {
  ec_assert(ctx->load, EC_EUNDEFINED, NULL);
  return ctx->load(id);
}

/**
 * Remove a certificate from the local store
 */
ec_err_t ec_store_remove(ec_ctx_t ctx, ec_id_t id) {
  ec_assert(ctx->remove, EC_EUNDEFINED, NULL);
  return ctx->remove(id);
}
