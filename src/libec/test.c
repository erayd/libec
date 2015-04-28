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
  printf("\n== Basic Tests ==\n");

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
  ec_abort((c_end = ec_import(buf, sizeof(buf), EC_IMPORT_CHAIN)) != NULL, "Import cert");
  c_end->signer = c_int;
  ec_abort(!ec_check(c_end, EC_CHECK_ALL & ~EC_CHECK_SECRET), "Cert still passes all checks");
  ec_abort(ec_check(c_end, EC_CHECK_SECRET) == EC_ENOSECRET, "Secret is not present");

  //export & import with chain
  memset(buf, 0, sizeof(buf));
  ec_abort(!ec_export(buf, c_end, EC_EXPORT_CHAIN | EC_EXPORT_TRUSTED), "Export cert with chain");
  ec_cert_destroy(c_end);
  ec_abort((c_end = ec_import(buf, sizeof(buf), EC_IMPORT_CHAIN)) != NULL, "Import cert with chain");
  ec_abort(c_end->signer && c_end->signer->signer, "Chain is present");
  ec_abort(!(c_end->signer->signer->flags & EC_CERT_TRUSTED), "CA trust flag is not present");
  c_end->signer->signer->flags |= EC_CERT_TRUSTED;
  ec_abort(!ec_check(c_end, EC_CHECK_ALL & ~EC_CHECK_SECRET), "Cert still passes all checks");

  //roles & grants
  ec_abort(!ec_role_has(c_end, "com.example.myRole.test"), "Test wildcard role");
  ec_abort(ec_role_has(c_end, "com.example.myOtherRole.test"), "Test wildcard fail");
  ec_abort(!ec_role_has(c_end, "com.example.myOtherRole"), "Test standard role");
}

/**
 * Storage tests
 */
void test_store(void) {
  printf("\n== Local Store Tests ==\n");

  //set up context
  ec_ctx_t ctx_trusted;
  ec_ctx_init(&ctx_trusted, EC_CTX_TRUSTED);
  ec_abort(!(mkdir("test_store", 0700) && errno != EEXIST), "Create local store directory");
  ec_abort(!ec_ctx_set_store(ctx_trusted, "file:test_store"), "Set up local cert store");

  //create & self-sign certificate
  ec_cert_t *ca = ec_cert();
  ec_abort(ca != NULL, "Create CA cert");
  ec_sign(ca, ca, 0, 0);

  //save & destroy cert
  ec_id_t ca_id;
  ec_cert_id(ca_id, ca);
  ec_abort(!ec_store_save(ctx_trusted, ca), "Save CA in local store");
  ec_cert_destroy(ca);

  //load cert
  ca = ec_store_load(ctx_trusted, ca_id);
  ec_abort(ca != NULL, "Load CA from local store");
  ec_abort(!ec_check(ca, EC_CHECK_ALL & ~EC_CHECK_SECRET), "Cert passes all checks");

}

/**
 * Main entry point
 */
int main(int argc, char **argv) {
  test_basic();
  test_store();

  return 0;
}
