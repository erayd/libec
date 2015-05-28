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
#include <talloc.h>
#include <sodium.h>
#include <string.h>

static int _compfn(void *key, void *ptr);
static int _talloc_destructor(ec_ctx_t *ptr);


/**
 * Skiplist compare
 */
static int _compfn(void *key, void *ptr) {
  ec_cert_t *c = ptr;
  return memcmp(key, c->pk, crypto_sign_PUBLICKEYBYTES);
}

/**
 * Talloc destructor
 */
static int _talloc_destructor(ec_ctx_t *ptr) {
  ec_ctx_destroy(ptr);
  return 0;
}

/**
 * Create a new context
 */
ec_ctx_t *ec_ctx_create(void) {
  ec_ctx_t *ctx = talloc_zero(NULL, ec_ctx_t);
  if(!ctx)
    ec_err_r(ENOMEM, NULL);
  ctx->certs = ec_sl_create(_compfn);

  //clean up on talloc free
  talloc_set_destructor(ctx, _talloc_destructor);

  return ctx;
}

/**
 * Destroy a context
 */
void ec_ctx_destroy(ec_ctx_t *ctx) {
  ec_sl_destroy(ctx->certs, (ec_sl_freefn_t)ec_cert_destroy);
  talloc_set_destructor(ctx, NULL); //don't call destructor twice
  talloc_free(ctx);
}

/**
 * Set autoloader
 */
void ec_ctx_autoload(ec_ctx_t *ctx, ec_autoload_t autoload) {
  ctx->autoload = autoload;
}


/**
 * Set validator
 */
void ec_ctx_validator(ec_ctx_t *ctx, ec_record_validator_t validator) {
  ctx->validator = validator;
}

/**
 * Set next context
 */
ec_ctx_t *ec_ctx_next(ec_ctx_t *ctx, ec_ctx_t *next) {
  return ctx->next = next;
}

/**
 * Save a certificate in the context store
 */
ec_cert_t *ec_ctx_save(ec_ctx_t *ctx, ec_cert_t *c) {
  if(c && !ec_sl_set(ctx->certs, ec_cert_id(c), c, (ec_sl_freefn_t)ec_cert_destroy)) {
    talloc_reparent(talloc_parent(c), ctx, c);
    return c;
  }
  return NULL;
}

/**
 * Remove a certificate from the context store, and return the certificate
 * if it exists
 */
ec_cert_t *ec_ctx_remove(ec_ctx_t *ctx, ec_id_t id) {
  ec_cert_t *c = ec_sl_remove(ctx->certs, id, NULL);
  if(c)
    talloc_reparent(ctx, NULL, c);
  return c;
}

/**
 * Get a certificate from the context store
 */
ec_cert_t *ec_ctx_cert(ec_ctx_t *ctx, ec_id_t id) {
  ec_cert_t *c = ec_sl_get(ctx->certs, id);
  //try autoloading if not found
  if(!c && ctx->autoload) {
    if(c = ctx->autoload(id))
      ec_ctx_save(ctx, c);
  }
  //try chained contexts
  if(!c && ctx->next)
    c = ec_ctx_cert(ctx->next, id);
  return c;
}

/**
 * Get the trust anchor for a certificate
 */
ec_cert_t *ec_ctx_anchor(ec_ctx_t *ctx, ec_cert_t *c) {
  if(!c || ec_cert_check(ctx, c, EC_CHECK_CHAIN))
    return NULL;
  while(!(c->flags & EC_CERT_TRUSTED))
    c = ec_ctx_cert(ctx, c->signer_id);
  return c;
}
