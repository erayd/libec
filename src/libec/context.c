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
#include <string.h>

ec_err_t ec_ctx_file_init(ec_ctx_t ctx, char *location);
ec_err_t ec_ctx_file_save(ec_ctx_t ctx, ec_cert_t *c);
ec_cert_t *ec_ctx_file_load(ec_ctx_t ctx, ec_id_t id);
ec_err_t ec_ctx_file_remove(ec_ctx_t ctx, ec_id_t id);

/**
 * Initialise a new context
 */
void ec_ctx_init(ec_ctx_t *ctx, int flags) {
  ec_abort(*ctx = calloc(1, sizeof(**ctx)), EC_ENOMEM, NULL);
  (*ctx)->flags = flags;
}

/**
 * Destroy a context
 */
void ec_ctx_destroy(ec_ctx_t ctx) {
  if(ctx->location)
    free(ctx->location);
  free(ctx);
}

/**
 * Set the certificate store location / type
 */
ec_err_t ec_ctx_set_store(ec_ctx_t ctx, char *store) {
  char method[strlent(store)];
  strcpy(method, store);
  char *location = strchr(method, ':');
  *location++ = '\0';

  if(!strcmp(method, "file")) {
    ctx->save = ec_ctx_file_save;
    ctx->load = ec_ctx_file_load;
    ctx->remove = ec_ctx_file_remove;
  }
  else
    return EC_EUNKNOWN;

  if(ctx->location)
    free(ctx->location);
  ec_abort(ctx->location = malloc(strlent(location)), EC_ENOMEM, NULL);
  strcpy(ctx->location, location);

  return EC_OK;
}

/**
 * Set the next context to search when loading certs if not found in this one
 */
void ec_ctx_set_next(ec_ctx_t ctx, ec_ctx_t next) {
  ctx->next = next;
}

/**
 * Save a certificate in the local store
 */
ec_err_t ec_store_save(ec_ctx_t ctx, ec_cert_t *c) {
  ec_abort(ctx->save, EC_EUNDEFINED, NULL);
  return ctx->save(ctx, c);
}

/**
 * Load a certificate from the local store
 */
ec_cert_t *ec_store_load(ec_ctx_t ctx, ec_id_t id) {
  ec_abort(ctx->load, EC_EUNDEFINED, NULL);
  ec_cert_t *c = ctx->load(ctx, id);
  if(!c)
    return ctx->next ? ec_store_load(ctx->next, id) : NULL;
  if(ctx->flags & EC_CTX_TRUSTED)
    c->flags |= EC_CERT_TRUSTED;
  if(!(c->flags & EC_CERT_TRUSTED)) {
    ec_id_t signer_id;
    if(!ec_cert_signer_id(signer_id, c)) {
      if(c->signer = ec_store_load(ctx, signer_id))
        c->flags |= EC_CERT_FSIGNER;
    }
  }
  return c;
}

/**
 * Remove a certificate from the local store
 */
ec_err_t ec_store_remove(ec_ctx_t ctx, ec_id_t id) {
  ec_abort(ctx->remove, EC_EUNDEFINED, NULL);
  return ctx->remove(ctx, id);
}
