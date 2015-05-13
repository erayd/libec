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

#include <include/common.h>
#include <talloc.h>
#include <string.h>

/**
 * Initialise channel
 */
ec_err_t ec_channel_init(ec_ctx_t *ctx, ec_channel_t *ch, ec_cert_t *c, unsigned char *dh) {
  //reset state & generate new keypair
  crypto_box_keypair(ch->pk, ch->sk);
  ch->state = START;
  ch->ctx = ctx;
  ch->c = c;

  //check cert
  if(ec_cert_check(NULL, ch->c, EC_CHECK_SECRET))
    return EC_ENOSK;

  //reset nonce & ctr
  ch->ctr = 1;
  randombytes_buf(ch->nonce_local, crypto_box_NONCEBYTES);
  memcpy(ch->nonce_local, &ch->ctr, sizeof(ch->ctr));

  //generate signed dh frame
  unsigned char *pos = dh;
  memcpy(pos, ec_cert_id(ch->c), EC_CERT_ID_BYTES); pos += EC_CERT_ID_BYTES;
  memcpy(pos, ch->pk, crypto_box_PUBLICKEYBYTES); pos += crypto_box_PUBLICKEYBYTES;
  memcpy(pos, ch->nonce_local, crypto_box_NONCEBYTES); pos += crypto_box_NONCEBYTES;
  crypto_sign_detached(pos, NULL, dh, pos - dh, ch->c->sk);
  if(crypto_sign_verify_detached(pos, dh, pos - dh, ch->c->pk))
    return EC_ESIGN;

  return EC_OK;
}

/**
 * Make channel ready for use (second half of D/H)
 */
ec_err_t ec_channel_start(ec_channel_t *ch, unsigned char *dh) {
  //fetch & verify remote cert, verify dh frame signature
  ec_cert_t *c = ec_ctx_cert(ch->ctx, dh);
  if(!c || ec_cert_check(ch->ctx, c, EC_CHECK_ALL))
    return EC_ECHAIN;
  const unsigned char *sig = dh + EC_CHANNEL_DH_BYTES - crypto_sign_BYTES;
  if(crypto_sign_verify_detached(sig, dh, sig - dh, c->pk))
    return EC_ESIGN;
  dh += EC_CERT_ID_BYTES;

  //import dh data & compute shared key
  memcpy(ch->pk, dh, crypto_box_PUBLICKEYBYTES); dh += crypto_box_PUBLICKEYBYTES;
  memcpy(ch->nonce_remote, dh, crypto_box_NONCEBYTES); dh += crypto_box_NONCEBYTES;
  if(crypto_box_beforenm(ch->key, ch->pk, ch->sk))
    return EC_ESODIUM;

  //ready to go :-)
  ch->state = READY;
  return EC_OK;
}

/**
 * Encrypt a buffer
 */
ec_err_t ec_channel_encrypt(ec_channel_t *ch, unsigned char *buf, size_t len,
  unsigned char *mac, uint64_t *ctr)
{
  if(ch->state != READY)
    return EC_EINIT;

  //set user ctr
  if(ctr)
    *ctr = ch->ctr;

  //encrypt
  crypto_box_detached_afternm(buf, mac, buf, len, ch->nonce_local, ch->key);

  //update ctr / nonce
  ch->ctr++;
  memcpy(ch->nonce_local, &ch->ctr, sizeof(ch->ctr));

  return EC_OK;
}

/**
 * Decrypt a buffer
 */
ec_err_t ec_channel_decrypt(ec_channel_t *ch, unsigned char *buf, size_t len,
  unsigned char *mac, uint64_t ctr)
{
  //set nonce & ctr
  if(ctr)
    memcpy(ch->nonce_remote, &ctr, sizeof(ctr));
  else
    memcpy(&ctr, ch->nonce_remote, sizeof(ctr));

  //decrypt
  if(crypto_box_open_detached_afternm(buf, buf, mac, len, ch->nonce_remote, ch->key))
    return EC_EMAC;

  //update nonce ctr
  ctr++;
  memcpy(ch->nonce_remote, &ctr, sizeof(ctr));

  return EC_OK;
}
