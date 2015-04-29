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

#include <ec.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

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

  //create & sign CA
  ec_cert_t *ca = ec_cert();
  ec_abort(ca != NULL, "Create CA");
  ca->flags |= EC_CERT_TRUSTED; //trust CA
  ec_abort(ec_role_grant(ca, "*") != NULL, "Add global grant");
  ec_abort(!ec_sign(ca, ca, 0, 0), "Self-sign CA");
  ec_abort(!ec_check(ca, EC_CHECK_ALL), "CA passes all checks");

  //create & sign intermediate cert
  ec_cert_t *c_int = ec_cert();
  ec_abort(c_int != NULL, "Create intermediate cert");
  ec_abort(ec_role_grant(c_int, "com.example.*") != NULL, "Add grant");
  ec_abort(!ec_sign(c_int, ca, 0, 0), "Sign intermediate cert");
  ec_abort(!ec_check(c_int, EC_CHECK_ALL), "Intermediate cert passes all checks");

  //create & sign end cert
  ec_cert_t *c_end = ec_cert();
  ec_abort(c_end != NULL, "Create certificate");
  ec_abort(ec_role_add(c_end, "com.example.myRole.*") != NULL, "Add wildcard role");
  ec_abort(ec_role_add(c_end, "com.example.myOtherRole") != NULL, "Add standard role");
  ec_abort(!ec_sign(c_end, c_int, 0, 0), "Sign cert using intermediate");
  ec_abort(!ec_check(c_end, EC_CHECK_ALL), "Cert passes all checks");

  //export & import
  unsigned char buf[ec_export_len(c_end, EC_EXPORT_CHAIN | EC_EXPORT_TRUSTED)];
  memset(buf, 0, sizeof(buf));
  ec_abort(!ec_export(buf, c_end, 0), "Export cert");
  ec_cert_destroy(c_end);
  ec_abort((c_end = ec_import(NULL, buf, sizeof(buf), EC_IMPORT_CHAIN)) != NULL, "Import cert");
  c_end->signer = c_int;
  ec_abort(!ec_check(c_end, EC_CHECK_ALL & ~EC_CHECK_SECRET), "Cert still passes all checks");
  ec_abort(ec_check(c_end, EC_CHECK_SECRET) == EC_ENOSECRET, "Secret is not present");

  //export & import with chain
  memset(buf, 0, sizeof(buf));
  ec_abort(!ec_export(buf, c_end, EC_EXPORT_CHAIN | EC_EXPORT_TRUSTED), "Export cert with chain");
  ec_cert_destroy(c_end);
  ec_abort((c_end = ec_import(NULL, buf, sizeof(buf), EC_IMPORT_CHAIN)) != NULL, "Import cert with chain");
  ec_abort(c_end->signer && c_end->signer->signer, "Chain is present");
  ec_abort(!(c_end->signer->signer->flags & EC_CERT_TRUSTED), "CA trust flag is not present");
  c_end->signer->signer->flags |= EC_CERT_TRUSTED;
  ec_abort(!ec_check(c_end, EC_CHECK_ALL & ~EC_CHECK_SECRET), "Cert still passes all checks");

  //roles & grants
  ec_abort(!ec_role_has(c_end, "com.example.myRole.test"), "Test wildcard role");
  ec_abort(ec_role_has(c_end, "com.example.myOtherRole.test"), "Test wildcard fail");
  ec_abort(!ec_role_has(c_end, "com.example.myOtherRole"), "Test standard role");

  //cleanup
  ec_cert_destroy(c_end);
  ec_cert_destroy(c_int);
  ec_cert_destroy(ca);
}

/**
 * Storage tests
 */
void test_store(void) {
  fprintf(stderr, "\n== Local Store Tests ==\n");

  //set up CA context
  ec_ctx_t ctx_trusted;
  ec_ctx_init(&ctx_trusted, EC_CTX_TRUSTED);
  ec_abort(!(mkdir("test_store", 0700) && errno != EEXIST), "Create local store directory");
  ec_abort(!(mkdir("test_store/trusted", 0700) && errno != EEXIST), "Create local store trusted directory");
  ec_abort(!ec_ctx_set_store(ctx_trusted, "file:test_store/trusted"), "Set up trusted local cert store");

  //create & self-sign CA
  ec_cert_t *ca = ec_cert();
  ec_abort(ca != NULL, "Create CA cert");
  ec_sign(ca, ca, 0, 0);

  //save CA
  ec_id_t ca_id;
  ec_cert_id(ca_id, ca);
  ec_abort(!ec_store_save(ctx_trusted, ca), "Save CA in trusted local store");

  //load CA
  ec_cert_t *ca_test = ec_store_load(ctx_trusted, ca_id);
  ec_abort(ca_test != NULL, "Load CA from local store");
  ec_abort(!ec_check(ca_test, EC_CHECK_ALL & ~EC_CHECK_SECRET), "CA passes all checks");
  ec_cert_destroy(ca_test);

  //set up untrusted context
  ec_ctx_t ctx;
  ec_ctx_init(&ctx, 0);
  ec_ctx_set_next(ctx, ctx_trusted);
  ec_abort(!(mkdir("test_store/user", 0700) && errno != EEXIST), "Create local store user directory");
  ec_abort(!ec_ctx_set_store(ctx, "file:test_store/user"), "Set up local cert store");

  //create & sign intermediate cert
  ec_cert_t *ca_int = ec_cert();
  ec_abort(ca_int != NULL, "Create intermediate CA");
  ec_sign(ca_int, ca, 0, 0);
  ec_abort(!ec_store_save(ctx, ca_int), "Save cert into local store");

  //create, sign & store end cert
  ec_cert_t *c = ec_cert();
  ec_abort(c != NULL, "Create certificate");
  ec_sign(c, ca_int, 0, 0);
  ec_abort(!ec_store_save(ctx, c), "Save cert into local store");

  //get cert id, then destroy all certs
  ec_id_t id;
  ec_cert_id(id, c);
  ec_cert_destroy(c);
  ec_cert_destroy(ca_int);
  ec_cert_destroy(ca);

  //load cert from store
  c = ec_store_load(ctx, id);
  ec_abort(c != NULL, "Load cert from local store");
  ec_abort(!ec_check(c, EC_CHECK_ALL & ~EC_CHECK_SECRET), "Cert passes all checks");
  
  //cleanup
  ec_cert_destroy(c);
  ec_ctx_destroy(ctx);
  ec_ctx_destroy(ctx_trusted);
}

/**
 * Main entry point
 */
int main(int argc, char **argv) {
  test_basic();
  test_store();

  return 0;
}
