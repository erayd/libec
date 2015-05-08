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

#include <include/ec.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * Print test result
 */
int ec_abort(int cond, char *message) {
  if(cond)
    fprintf(stderr, "\033[32mOK\033[0m %s\n", message);
  else
    fprintf(stderr, "\033[1m\033[31mEE %s\033[0m\n", message);
  if(!cond)
    exit(EXIT_FAILURE);
  return cond;
}

/**
 * Basic tests
 */
void test_basic(void) {
  fprintf(stderr, "\n== Basic Tests ==\n");

  //create a new context stack
  ec_ctx_t *ctx = ec_ctx_create();
  ec_ctx_t *ctx_trusted = ctx->next = ec_ctx_create();

  //create & self-sign CA
  ec_cert_t *ca = ec_ctx_save(ctx_trusted, ec_cert_create(0, 0));
  ec_abort(ca != NULL, "Create CA in trusted context");
  ca->flags |= EC_CERT_TRUSTED;
  ec_abort(ec_role_grant(ca, "*") != NULL, "Add global grant");
  ec_abort(!ec_cert_sign(ca, ca), "Self-sign CA");
  ec_abort(!ec_cert_check(ctx, ca, EC_CHECK_ALL | EC_CHECK_SECRET), "CA passes all checks");

  //create & sign intermediate CA
  ec_cert_t *ca_int = ec_ctx_save(ctx, ec_cert_create(0, 0));
  ec_abort(ca_int != NULL, "Create intermediate CA");
  ec_abort(ec_role_add(ca_int, "com.esspermitted.goFishing") != NULL, "Add standard role");
  ec_abort(ec_role_grant(ca_int, "com.example.*") != NULL, "Add wildcard grant for com.example.*");
  ec_abort(!ec_cert_sign(ca_int, ca), "Sign intermediate CA");
  ec_abort(!ec_cert_check(ctx, ca_int, EC_CHECK_ALL | EC_CHECK_SECRET), "Intermediate CA passes all checks");
  

  //create invalid cert
  ec_cert_t *c = ec_ctx_save(ctx, ec_cert_create(0, 0));
  ec_abort(c != NULL, "Create user cert");
  ec_abort(ec_role_add(c, "com.accessdenied.goFishing") != NULL, "Add invalid standard role");
  ec_abort(!ec_cert_sign(c, ca_int), "Sign user cert");
  ec_abort(ec_cert_check(ctx, c, EC_CHECK_ALL | EC_CHECK_SECRET) == EC_EGRANT,
    "User cert fails with EC_EGRANT");

  //create valid cert
  c = ec_ctx_save(ctx, ec_cert_create(0, 0));
  ec_abort(c != NULL, "Create another user cert");
  ec_abort(ec_role_add(c, "com.example.goFishing") != NULL, "Add valid standard role");
  ec_abort(!ec_cert_sign(c, ca_int), "Sign user cert");
  ec_abort(!ec_cert_check(ctx, c, EC_CHECK_ALL | EC_CHECK_SECRET), "User cert passes all checks");

  //export & import
  unsigned char buf[ec_export_len(c, EC_EXPORT_SECRET)];
  ec_abort(ec_export(buf, c, EC_EXPORT_SECRET), "Export cert with secret");
  ec_abort((c = ec_ctx_save(ctx, ec_import(buf, sizeof(buf)))) != NULL, "Import cert");
  ec_abort(!ec_cert_check(ctx, c, EC_CHECK_ALL | EC_CHECK_SECRET), "Imported cert passes all checks");

  char buf64[ec_export_len_64(c, EC_EXPORT_SECRET)];
  ec_abort(ec_export_64(buf64, c, EC_EXPORT_SECRET) != NULL, "Export cert to base64");
  ec_abort((c = ec_ctx_save(ctx, ec_import_64(buf64, sizeof(buf64)))) != NULL, "Import cert from base64");
  ec_abort(!ec_cert_check(ctx, c, EC_CHECK_ALL | EC_CHECK_SECRET), "Imported cert passes all checks");

  //cleanup
  ec_ctx_destroy(ctx_trusted);
  ec_ctx_destroy(ctx);
}

/**
 * Main entry point
 */
int main(int argc, char **argv) {
  test_basic();

  return 0;
}
