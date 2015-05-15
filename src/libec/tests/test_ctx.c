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
#include <string.h>

ec_cert_t *c_al = NULL;
ec_cert_t *autoload(ec_id_t id) {
  if(c_al && !memcmp(id, ec_cert_id(c_al), EC_CERT_ID_BYTES))
    return c_al;
  return NULL;
}

/**
 * Test contexts
 */
int main(void) {
  ec_abort(!ec_init(), "Initialise library");

  ec_ctx_t *ctx = ec_ctx_create();
  ec_abort(ctx, "Create context");

  //bulk save
  for(int i = 0; i < 100; i++) {
    ec_cert_t *c = ec_ctx_save(ctx, ec_cert_create(0, 0));
    if(!c)
      ec_abort(c, "Create & save 100 certificates");
  }

  //save / retrieve
  ec_cert_t *c = ec_ctx_save(ctx, ec_cert_create(0, 0));
  ec_abort(c, "Create target certificate");
  ec_cert_t *c_fromctx = ec_ctx_cert(ctx, ec_cert_id(c));
  ec_abort(c_fromctx, "Load cert from context");
  ec_abort(c == c_fromctx, "Correct certificate is retrieved");

  //chained search
  ec_ctx_t *chain = ec_ctx_create();
  ec_abort(chain, "Create context");
  ec_ctx_next(chain, ctx);
  ec_cert_t *c_fromchain = ec_ctx_cert(chain, ec_cert_id(c));
  ec_abort(c == c_fromchain, "Retrieve correct certificate via chained context");

  //autoload
  ec_ctx_autoload(ctx, autoload);
  ec_abort(c == ec_ctx_cert(chain, ec_cert_id(c)), "Retrieve correct certificate via chained context");
  c_al = ec_cert_create(0, 0);
  ec_abort(c_al, "Create autoload certificate");
  ec_abort(c_al == ec_ctx_cert(chain, ec_cert_id(c_al)), "Retrieve correct certificate via autoload");

  //cleanup
  ec_ctx_destroy(chain);
  ec_ctx_destroy(ctx);

  return 0;
}
