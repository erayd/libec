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
 * Test roles & grants
 */
int main(void) {
  //create context, ca & int cert
  ec_ctx_t *ctx = ec_ctx_create();
  ec_abort(ctx, "Create context");
  ec_cert_t *c = ec_ctx_save(ctx, ec_cert_create(0, 0));
  ec_abort(c, "Create CA");
  c->flags |= EC_CERT_TRUSTED;
  ec_abort(ec_role_grant(c, "com.example.*"), "Add grant for com.example.*");
  ec_abort(!ec_cert_sign(c, c), "Self-sign CA");
  ec_cert_t *ca = c;
  ec_abort(c = ec_ctx_save(ctx, ec_cert_create(0, 0)), "Create intermediate certificate");
  ec_abort(ec_role_add(c, "com.example.one"), "Add role com.example.one");
  ec_abort(ec_role_grant(c, "com.example.two"), "Add grant for com.example.two");
  ec_abort(ec_role_grant(c, "com.example.three.*"), "Add grant for com.example.three.*");
  ec_abort(!ec_cert_sign(c, ca), "Sign intermediate certificate");
  ca = c;

  //create end cert, test roles
  ec_abort(c = ec_ctx_save(ctx, ec_cert_create(0, 0)), "Create certificate");
  ec_abort(ec_role_add(c, "com.example.two"), "Add role for com.exmaple.two");
  ec_abort(ec_role_add(c, "com.example.three.four.*"), "Add role for com.example.three.four.*");
  ec_abort(ec_role_add(c, "com.example.three.five"), "Add role for com.example.three.five");
  ec_abort(!ec_cert_sign(c, ca), "Sign certificate");
  ec_abort(!ec_cert_check(ctx, c, EC_CHECK_ROLE), "Validate roles");

  //check non-defined roles
  ec_abort(!ec_role_has(c, "com.example.two"), "Role com.example.two is present");
  ec_abort(ec_role_has(c, "com.example.three.six"), "Role com.example.three.six is missing");
  ec_abort(!ec_role_has(c, "com.example.three.four.seven"), "Role com.example.three.four.seven is present");

  return 0;
}
