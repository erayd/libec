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
#include <time.h>

/**
 * Test basic certificate functionality
 */
int main(void) {
  //basic functionality
  ec_cert_t *c = ec_cert_create(0, 0);
  ec_abort(c, "Create certificate");
  c->flags |= EC_CERT_TRUSTED;
  ec_abort(!ec_cert_sign(c, c), "Self-sign cert");
  ec_abort(!ec_cert_check(NULL, c, EC_CHECK_CERT | EC_CHECK_SECRET | EC_CHECK_SIGN),
    "Cert passes local checks");
  ec_cert_destroy(c);

  //valid_from in future
  c = ec_cert_create(time(NULL) + 10, 0);
  ec_abort(c, "Create certificate");
  ec_abort(ec_cert_check(NULL, c, EC_CHECK_CERT) == EC_EFUTURE, "Check fails with EC_EFUTURE");
  ec_cert_destroy(c);

  //valid_until in past
  c = ec_cert_create(time(NULL) - 100, time(NULL) - 10);
  ec_abort(c, "Create certificate");
  ec_abort(ec_cert_check(NULL, c, EC_CHECK_CERT) == EC_EEXPIRED, "Check fails with EC_EEXPIRED");
  ec_cert_destroy(c);

  return 0;
}
