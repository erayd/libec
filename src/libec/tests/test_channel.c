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

/**
 * Test channels
 */
int main(void) {
  //environment
  ec_abort(!ec_init(), "Initialise libec");
  ec_ctx_t *ctx = ec_ctx_create();
  ec_abort(ctx, "Create context");

  //create certificates
  ec_cert_t *ca = ec_ctx_save(ctx, ec_cert_create(0, 0));
  ec_abort(ca, "Create CA");
  ca->flags |= EC_CERT_TRUSTED;
  ec_abort(!ec_cert_sign(ca, ca), "Sign CA");
  ec_cert_t *local = ec_ctx_save(ctx, ec_cert_create(0, 0));
  ec_abort(local, "Create local certificate");
  ec_abort(!ec_cert_sign(local, ca), "Sign local certificate");
  ec_cert_t *remote = ec_ctx_save(ctx, ec_cert_create(0, 0));
  ec_abort(remote, "Create remote certificate");
  ec_abort(!ec_cert_sign(remote, ca), "Sign remote certificate");

  //channel setup
  ec_channel_t local_ch;
  unsigned char local_dh[EC_CHANNEL_DH_BYTES];
  ec_abort(!ec_channel_init(&local_ch, local, ctx, local_dh), "Initialise local channel");
  ec_channel_t remote_ch;
  unsigned char remote_dh[EC_CHANNEL_DH_BYTES];
  ec_abort(!ec_channel_init(&remote_ch, remote, ctx, remote_dh), "Initialise remote channel");
  ec_abort(!ec_channel_start(&local_ch, remote_dh, EC_CHECK_ALL & ~EC_CHECK_REQUIRE), "Finish local D/H");
  ec_abort(!ec_channel_start(&remote_ch, local_dh, EC_CHECK_ALL & ~EC_CHECK_REQUIRE), "Finish remote D/H");
  ec_abort(!memcmp(local_ch.key, remote_ch.key, crypto_box_BEFORENMBYTES), "Computed keys match");

  //remote cert matches
  ec_abort(!memcmp(ec_cert_id(remote), ec_cert_id(ec_channel_remote(&local_ch)),
      EC_CERT_ID_BYTES), "Remote certificate matches");

  //crypto tests
  unsigned char buf[1000];
  unsigned char buf_cmp[sizeof(buf)];
  unsigned char mac[crypto_box_MACBYTES];
  for(int i = 0; i < 2; i++) {
    randombytes_buf(buf, sizeof(buf));
    memcpy(buf_cmp, buf, sizeof(buf));
    ec_abort(!ec_channel_encrypt(&local_ch, buf, sizeof(buf), mac, NULL), "Encrypt to remote");
    ec_abort(memcmp(buf, buf_cmp, sizeof(buf)), "Buffer has changed");
    ec_abort(!ec_channel_decrypt(&remote_ch, buf, sizeof(buf), mac, 0), "Decrypt from local");
    ec_abort(!memcmp(buf, buf_cmp, sizeof(buf)), "Buffer matches original data");
  }

  //cleanup
  ec_ctx_destroy(ctx);

  return 0;
}
