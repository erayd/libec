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
 * Test export & import
 */
int main(void) {
  ec_ctx_t *ctx = ec_ctx_create();
  ec_abort(ctx, "Create context");
  ec_cert_t *ca = ec_ctx_save(ctx, ec_cert_create(0, 0));
  ca->flags |= EC_CERT_TRUSTED;
  ec_abort(ec_role_grant(ca, "*"), "Add global grant");
  ec_abort(!ec_cert_sign(ca, ca), "Self-sign CA");
  
  ec_cert_t *c = ec_ctx_save(ctx, ec_cert_create(0, 0));
  ec_abort(c, "Create cert");
  ec_abort(ec_role_add(c, "com.example.role"), "Add role");
  ec_abort(!ec_cert_sign(c, ca), "Sign cert");

  char buf[ec_export_len_64(c, EC_EXPORT_SECRET)];
  ec_abort(ec_export_64(buf, c, EC_EXPORT_SECRET), "Export cert");
  ec_abort(c = ec_import_64(buf, sizeof(buf)), "Import cert");
  ec_abort(!ec_cert_check(ctx, c, EC_CHECK_ALL | EC_CHECK_SECRET), "Cert passes all checks");

  return 0;
}
