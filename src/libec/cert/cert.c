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
#include <time.h>

static ec_err_t ec_cert_cryptsk_toggle(ec_cert_t *c, char *password);

/**
 * Create a new certificate
 */
ec_cert_t *ec_cert_create(time_t valid_from, time_t valid_until) {
  ec_cert_t *c = talloc_zero(NULL, ec_cert_t);
  if(!c)
    ec_err_r(ENOMEM, NULL, NULL);
  c->pk = talloc_size(c, crypto_sign_PUBLICKEYBYTES);
  c->sk = talloc_size(c, crypto_sign_SECRETKEYBYTES);
  c->salt = talloc_size(c, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
  if(!c->pk || !c->sk || !c->salt) {
    talloc_free(c);
    return NULL;
  }
  randombytes_buf(c->salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
  crypto_sign_ed25519_keypair(c->pk, c->sk);
  c->valid_from = valid_from ?: time(NULL);
  c->valid_until = valid_until ?: ~0LL;
  c->version = EC_LAYOUT_VERSION;
  return c;
}

/**
 * Destroy a certificate
 */
void ec_cert_destroy(ec_cert_t *c) {
  if(c->sk)
    memset(c->sk, 0, crypto_sign_SECRETKEYBYTES);
  talloc_free(c);
}

//hash a certificate
ec_err_t ec_cert_hash(unsigned char *hash, ec_cert_t *c) {
  //check required data fields
  if(!c->pk || !c->signer_id)
    return EC_ENOPK;

  //pre-process fields
  uint8_t sign_flags = c->flags & ~EC_CERT_CRYPTSK;

  //generate hash
  crypto_generichash_state state;
  crypto_generichash_init(&state, NULL, 0, EC_METHOD_BLAKE2B_512_BYTES);
  //version, flags, validity period
  crypto_generichash_update(&state, (unsigned char*)&c->version, sizeof(c->version));
  crypto_generichash_update(&state, (unsigned char*)&sign_flags, sizeof(sign_flags));
  crypto_generichash_update(&state, (unsigned char*)&c->valid_from, sizeof(c->valid_from));
  crypto_generichash_update(&state, (unsigned char*)&c->valid_until, sizeof(c->valid_until));
  //pk & signer pk
  crypto_generichash_update(&state, c->pk, crypto_sign_PUBLICKEYBYTES);
  crypto_generichash_update(&state, c->signer_id, crypto_sign_PUBLICKEYBYTES);
  //records
  for(ec_record_t *r = ec_cert_records(c); r; r = r->next) {
    //don't hash NOSIGN records
    if(r->flags & EC_RECORD_NOSIGN)
      continue;
    uint8_t hash_flags = r->flags & 0xFF;
    crypto_generichash_update(&state, r->key, r->key_len);
    crypto_generichash_update(&state, r->data, r->data_len);
    crypto_generichash_update(&state, (unsigned char*)&r->key_len, sizeof(r->key_len));
    crypto_generichash_update(&state, (unsigned char*)&r->data_len, sizeof(r->data_len));
    crypto_generichash_update(&state, (unsigned char*)&hash_flags, sizeof(hash_flags));
  }
  crypto_generichash_final(&state, hash, EC_METHOD_BLAKE2B_512_BYTES);

  return EC_OK;
}

/**
 * Sign a certificate
 */
ec_err_t ec_cert_sign(ec_cert_t *c, ec_cert_t *signer) {
  //check signer & cert for basic validity
  rfail(ec_cert_check(NULL, c, EC_CHECK_CERT));
  rfail(ec_cert_check(NULL, signer, EC_CHECK_CERT | EC_CHECK_SECRET));
  if(signer->flags & EC_CERT_CRYPTSK)
    return EC_ELOCKED;

  //clamp validity period
  if(c->valid_from > signer->valid_from)
    c->valid_from = signer->valid_from;
  if(c->valid_until > signer->valid_until)
    c->valid_until = signer->valid_until;

  //add signer data
  if(!(c->signer_id = talloc_size(c, crypto_sign_PUBLICKEYBYTES)))
    ec_err_r(ENOMEM, EC_ENOMEM, NULL);
  memcpy(c->signer_id, ec_cert_id(signer), EC_CERT_ID_BYTES);

  //generate hash
  unsigned char hash[EC_METHOD_BLAKE2B_512_BYTES];
  rfail(ec_cert_hash(hash, c));

  //sign
  if(!(c->signature = talloc_size(c, crypto_sign_BYTES)))
    ec_err_r(ENOMEM, EC_ENOMEM, NULL);
  crypto_sign_detached(c->signature, NULL, hash, sizeof(hash), signer->sk);

  //check signature
  if(crypto_sign_verify_detached(c->signature, hash, sizeof(hash), c->signer_id))
    return EC_ESIGN;

  return EC_OK;
}

/**
 * Check a certificate
 */
ec_err_t ec_cert_check(ec_ctx_t *ctx, ec_cert_t *c, int flags) {
  //always perform basic checks
  flags |= EC_CHECK_CERT;

  //ROLE implies CHAIN
  if(flags & EC_CHECK_ROLE)
    flags |= EC_CHECK_CHAIN;

  //CHAIN implies SIGN
  if(flags & EC_CHECK_CHAIN)
    flags |= EC_CHECK_SIGN;

  //some checks require a context
  if((flags & (EC_CHECK_CHAIN | EC_CHECK_ROLE)) && !ctx)
    return EC_ENOCTX;

  //basic checks
  if(flags & EC_CHECK_CERT) {
    //version is EC_LAYOUT_VERSION
    if(c->version != EC_LAYOUT_VERSION)
      return EC_EVERSION;

    //validity period has started
    if(c->valid_from > time(NULL))
      return EC_EFUTURE;

    //validity period has not yet ended
    if(c->valid_until < time(NULL))
      return EC_EEXPIRED;

    //public key is present
    if(!c->pk)
      return EC_ENOPK;

    //iterate records
    for(ec_record_t *r = ec_cert_records(c); r; r = r->next) {

      //records are the correct length
      if(r->key_len > EC_RECORD_KMAX || r->data_len > EC_RECORD_DMAX)
        return EC_ERECORD;

      //section start records have a valid string key
      if((r->flags & EC_RECORD_SECTION) && !isstr(r->key, r->key_len))
        return EC_ERECORD;
    }
  }

  //check secret
  if(flags & EC_CHECK_SECRET) {
    //secret key is present
    if(!c->sk)
      return EC_ENOSK;
  }

  //check signature
  if(flags & EC_CHECK_SIGN) {
    //signer id is present
    if(!c->signer_id)
      return EC_ESIGNER;

    //signature is present
    if(!c->signature)
      return EC_ENOSIGN;

    //hash cert
    unsigned char hash[EC_METHOD_BLAKE2B_512_BYTES];
    rfail(ec_cert_hash(hash, c));

    //signer cert is available
    ec_cert_t *signer = NULL;
    if(!memcmp(ec_cert_id(c), c->signer_id, EC_CERT_ID_BYTES))
      signer = c; //self-signed
    else if(ctx)
      signer = ec_ctx_cert(ctx, c->signer_id); //context store
    if(!signer)
      return EC_ESIGNER;

    //validity period falls withing signer validity period
    if(c->valid_from < signer->valid_from || c->valid_until > signer->valid_until)
      return EC_EVALIDITY;

    //signature is valid
    if(crypto_sign_verify_detached(c->signature, hash, sizeof(hash), signer->pk))
      return EC_ESIGN;
  }

  //check trust chain
  if(flags & EC_CHECK_CHAIN && !(c->flags & EC_CERT_TRUSTED)) {
    //cannot be self-signed
    if(!memcmp(ec_cert_id(c), c->signer_id, EC_CERT_ID_BYTES))
      return EC_ESELF;

    //signer must pass every check that c does (except SECRET)
    if(ec_cert_check(ctx, ec_ctx_cert(ctx, c->signer_id), flags & ~EC_CHECK_SECRET))
      return EC_ECHAIN;
    
  }

  //roles & grants
  if(flags & EC_CHECK_ROLE) {
    ec_cert_t *signer = ec_ctx_cert(ctx, c->signer_id);

    //iterate grants
    for(ec_record_t *r = ec_match_bin(ec_cert_records(c), "_grant", 0, NULL, 0, NULL, 0);
      r && !(r->flags & EC_RECORD_SECTION); r = r->next)
    {

      //grants must have a valid string key
      if(!isstr(r->key, r->key_len))
        return EC_ERECORD;

      //grants must be granted in turn by the signer unless the cert is a trusted root
      if(!(c->flags & EC_CERT_TRUSTED) && ec_role_has_grant(signer, (char*)r->key))
        return EC_EGRANT;
    }

    //iterate roles
    for(ec_record_t *r = ec_match_bin(ec_cert_records(c), "_role", 0, NULL, 0, NULL, 0);
      r && !(r->flags & EC_RECORD_SECTION); r = r->next)
    {

      //roles must have a valid string key
      if(!isstr(r->key, r->key_len))
        return EC_ETYPE;

      //roles must be granted by the signer unless the cert is a trusted root
      if(!(c->flags & EC_CERT_TRUSTED) && ec_role_has_grant(signer, (char*)r->key))
        return EC_EGRANT;
    }
  }

  //all OK
  return EC_OK;
}

/**
 * Get the unique ID for a certificate - uses ed25519 public key by default
 */
ec_id_t ec_cert_id(ec_cert_t *c) {
  ec_abort(EC_CERT_ID_BYTES == crypto_sign_PUBLICKEYBYTES, EC_ESIZE, NULL);
  return c->pk;
}

/**
 * Get the record list for a certificate
 */
ec_record_t *ec_cert_records(ec_cert_t *c) {
  return c->records;
}

/**
 * Toggle secret key encryption
 */
static ec_err_t ec_cert_cryptsk_toggle(ec_cert_t *c, char *password) {
  if(!c->sk)
    return EC_ENOSK;
  if(!c->salt)
    return EC_ENOSALT;
  unsigned char key[crypto_sign_SECRETKEYBYTES];
  if(crypto_pwhash_scryptsalsa208sha256(key, sizeof(key), password, strlen(password), c->salt,
      crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
      crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE))
    return EC_ENOMEM;
  for(int i = 0; i < sizeof(key); i++)
    c->sk[i] ^= key[i];
  memset(key, 0, sizeof(key));
  c->flags ^= EC_CERT_CRYPTSK;
  return EC_OK;
}

/**
 * Encrypt a secret key
 */
ec_err_t ec_cert_lock(ec_cert_t *c, char *password) {
  if(c->flags & EC_CERT_CRYPTSK)
    return EC_ELOCKED;
  return ec_cert_cryptsk_toggle(c, password);
}

/**
 * Decrypt a secret key
 */
ec_err_t ec_cert_unlock(ec_cert_t *c, char *password) {
  if(!(c->flags & EC_CERT_CRYPTSK))
    return EC_OK; //not locked
  return ec_cert_cryptsk_toggle(c, password);
}

/**
 * Copy a certificate
 */
ec_cert_t *ec_cert_copy(ec_cert_t *c) {
  // Abuse the export / import functions for the sake of maintainability. Slight
  // overhead from extra checks etc. involved with export / import, but obviates
  // the need for yet another certificate-construction implementation, and makes
  // copying simple.
  unsigned char buf[ec_export_len(c, EC_EXPORT_SECRET)];
  if(!ec_export(buf, c, EC_EXPORT_SECRET))
    return NULL;
  return ec_import(buf, sizeof(buf), NULL);
}
