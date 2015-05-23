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

#include <tests.h>

/**
 * Test certificate chains
 */
int main(void) {
  ec_abort(!ec_init(), "Initialise library");

  //create context
  ec_ctx_t *ctx = ec_ctx_create();
  ec_abort(ctx, "Create context");

  //create CA
  ec_cert_t *ca = ec_ctx_save(ctx, ec_cert_create(0, 0));
  ec_abort(ca, "Create CA");
  ca->flags |= EC_CERT_TRUSTED;
  ec_abort(!ec_cert_sign(ca, ca), "Self-sign CA");

  //create intermediate CA
  ec_cert_t *c_int = ec_ctx_save(ctx, ec_cert_create(0, 0));
  ec_abort(c_int, "Create intermediate cert");
  ec_abort(!ec_cert_sign(c_int, ca), "Sign intermediate cert");

  ec_cert_t *c = ec_ctx_save(ctx, ec_cert_create(0, 0));
  ec_abort(c, "Create certificate");
  ec_abort(!ec_cert_sign(c, c_int), "Sign certificate");

  //check chain
  ec_abort(!ec_cert_check(ctx, c, EC_CHECK_CERT | EC_CHECK_SIGN | EC_CHECK_CHAIN), "Chain validates OK");

  //CA is correct
  ec_abort(ec_ctx_anchor(ctx, c) == ca, "CA is correct");

  //cleanup
  ec_ctx_destroy(ctx);

  return 0;
}
