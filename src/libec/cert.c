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

#include <common.h>
#include <malloc.h>
#include <sodium.h>
#include <string.h>
#include <time.h>

/**
 * Create a new certificate
 */
ec_cert_t *ec_cert(void) {
  ec_cert_t *c = calloc(1, sizeof(*c));
  ec_assert(c, EC_ENOMEM, NULL);
  c->version = EC_CERT_VERSION;
  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
  crypto_sign_keypair(pk, sk);
  ec_append(c, "_cert", ec_record(0, (unsigned char*)"type", 0, (unsigned char*)EC_TYPE_ED25519, 0));
  ec_append(c, "_cert", ec_record(EC_RECORD_DCOPY, (unsigned char*)"key", 0, pk, sizeof(pk)));
  ec_append(c, NULL, ec_record(EC_RECORD_SECTION | EC_RECORD_INHERIT | EC_RECORD_NOSIGN, (unsigned char*)"_secret", 0, NULL, 0));
  ec_append(c, "_secret", ec_record(EC_RECORD_DCOPY, (unsigned char*)"key", 0, sk, sizeof(sk)));
  return c;
}

/**
 * Get the unique ID for a certificate and store into 'id'
 */
void ec_cert_id(ec_id_t id, ec_cert_t *c) {
  //type is currently always ed25519, so just get the pk and use that
  ec_assert(crypto_sign_PUBLICKEYBYTES == 32, EC_ESIZE, NULL);
  ec_record_t *pk = ec_match(c->records, "_cert", 0, (unsigned char*)"key", 0, NULL, crypto_sign_PUBLICKEYBYTES);
  ec_assert(pk, EC_EINVALID, NULL);
  memcpy(id, pk->data, pk->data_len);
}

/**
 * Sign a certificate
 */
ec_err_t ec_sign(ec_cert_t *c, ec_cert_t *signer, uint64_t valid_from, uint64_t valid_until) {
  //sanitise validity period
  if(!valid_from)
    valid_from = time(NULL);
  if(!valid_until)
    valid_until = valid_from + EC_DEFAULT_VALIDITY;

  //sanity checks
  rfail(ec_check(c, EC_CHECK_CERT));
  rfail(ec_check(signer, EC_CHECK_CERT | EC_CHECK_SECRET));

  //append signature type, validity period, & signer PK
  ec_record_t *signer_pk = ec_match(signer->records, "_cert", 0, (unsigned char*)"key", 0, NULL, 0);
  ec_append(c, "_sign", ec_record(EC_RECORD_DCOPY, (unsigned char*)"key", 0, signer_pk->data, signer_pk->data_len));
  ec_record_t *signer_type = ec_match(signer->records, "_cert", 0, (unsigned char*)"type", 0, NULL, 0);
  ec_append(c, "_sign", ec_record(EC_RECORD_DCOPY, (unsigned char*)"type", 0, signer_type->data, signer_type->data_len));
  ec_append(c, "_sign", ec_record(0, (unsigned char*)"method", 0, (unsigned char*)EC_METHOD_BLAKE2B_512, 0));
  ec_append(c, "_sign", ec_record(EC_RECORD_DCOPY, (unsigned char*)"from", 0, (unsigned char*)&valid_from, sizeof(valid_from)));
  ec_append(c, "_sign", ec_record(EC_RECORD_DCOPY, (unsigned char*)"until", 0, (unsigned char*)&valid_until, sizeof(valid_until)));

  //generate signature
  ec_record_t *signer_sk = ec_match(signer->records, "_secret", EC_RECORD_NOSIGN, (unsigned char*)"key", 0, NULL, crypto_sign_SECRETKEYBYTES);
  unsigned char hash[EC_METHOD_BLAKE2B_512_BYTES];
  if(ec_method_blake2b_512_hash(hash, c))
    return EC_EINTERNAL;
  unsigned char signature[crypto_sign_BYTES];
  crypto_sign_detached(signature, NULL, hash, EC_METHOD_BLAKE2B_512_BYTES, signer_sk->data);

  //append signature & add signer to cert
  ec_append(c, "_sign", ec_record(EC_RECORD_NOSIGN | EC_RECORD_DCOPY, (unsigned char*)"signature", 0, signature, sizeof(signature)));
  c->signer = signer;

  //check signature
  return ec_check(c, EC_CHECK_SIGNED);
}

/**
 * Check a certificate
 */
ec_err_t ec_check(ec_cert_t *c, int checks) {
  //always perform basic checks
  checks |= EC_CHECK_CERT;

  //ROLE imples CHAIN
  if(checks & EC_CHECK_ROLE)
    checks |= EC_CHECK_CHAIN;

  //CHAIN implies SIGNED
  if(checks & EC_CHECK_CHAIN)
    checks |= EC_CHECK_SIGNED;

  //basic checks
  if(checks & EC_CHECK_CERT) {

    //iterate records
    for(ec_record_t *r = c->records; r; r = r->next) {

      //records are the correct length
      if(r->key_len > EC_RECORD_KMAX || r->data_len > EC_RECORD_DMAX)
        return EC_ERECORD;

      //section start records have a valid string key
      if((r->flags & EC_RECORD_SECTION) && !isstr(r->key, r->key_len))
        return EC_ERECORD;
    }

    //public key type is ed25519
    if(!ec_match(c->records, "_cert", 0, (unsigned char*)"type", 0, (unsigned char*)EC_TYPE_ED25519, 0))
      return EC_ETYPE;

    //public key is present and correct
    if(!ec_match(c->records, "_cert", 0, (unsigned char*)"key", 0, NULL, crypto_sign_PUBLICKEYBYTES))
      return EC_ENOPUBLIC;
  }

  //secret key
  if(checks & EC_CHECK_SECRET) {

    //secret key is present and correct
    if(!ec_match(c->records, "_secret", EC_RECORD_NOSIGN, (unsigned char*)"key", 0, NULL, crypto_sign_SECRETKEYBYTES))
      return EC_ENOSECRET;
  }

  //signature
  if(checks & EC_CHECK_SIGNED) {

    //signature type is ed25519
    if(!ec_match(c->records, "_sign", 0, (unsigned char*)"type", 0, (unsigned char*)EC_TYPE_ED25519, 0))
      return EC_ETYPE;

    //signing method is blake2b_512
    if(!ec_match(c->records, "_sign", 0, (unsigned char*)"method", 0, (unsigned char*)EC_METHOD_BLAKE2B_512, 0))
      return EC_EMETHOD;

    //valid_from is present and not in the future
    uint64_t valid_from;
    ec_record_t *valid_from_r = ec_match(c->records, "_sign", 0, (unsigned char*)"from", 0, NULL, sizeof(valid_from));
    if(!valid_from_r)
      return EC_ENOVALIDITY;
    memcpy(&valid_from, valid_from_r->data, sizeof(valid_from));
    if(valid_from > time(NULL))
      return EC_EFUTURE;

    //valid_until is present and not in the past
    uint64_t valid_until;
    ec_record_t *valid_until_r = ec_match(c->records, "_sign", 0, (unsigned char*)"until", 0, NULL, sizeof(valid_until));
    if(!valid_until_r)
      return EC_ENOVALIDITY;
    memcpy(&valid_until, valid_until_r->data, sizeof(valid_until));
    if(valid_until < time(NULL))
      return EC_EEXPIRED;

    //signer pk is present
    ec_record_t *signer_pk = ec_match(c->records, "_sign", 0, (unsigned char*)"key", 0, NULL, crypto_sign_PUBLICKEYBYTES);
    if(!signer_pk)
      return EC_ENOPUBLIC;

    //signature is present
    ec_record_t *signature = ec_match(c->records, "_sign", EC_RECORD_NOSIGN, (unsigned char*)"signature", 0, NULL, crypto_sign_BYTES);
    if(!signature)
      return EC_ENOSIGNATURE;

    //signature is valid
    unsigned char hash[EC_METHOD_BLAKE2B_512_BYTES];
    rfail(ec_method_blake2b_512_hash(hash, c));
    if(crypto_sign_verify_detached(signature->data, hash, EC_METHOD_BLAKE2B_512_BYTES, signer_pk->data))
      return EC_ESIGNATURE;
  }

  //trust chain (only checked if cert is not a trusted root)
  if((checks & EC_CHECK_CHAIN) && !(c->flags & EC_CERT_TRUSTED)) {

    //chain is present
    if(!c->signer)
      return EC_ENOCHAIN;

    //signer chain is not self
    if(ec_certcmp(c, c->signer))
      return EC_ESELF;

    //linked signer PK must match PK in signature
    ec_record_t *signer_pk = ec_match(c->signer->records, "_cert", 0, (unsigned char*)"key", 0, NULL, 0);
    ec_record_t *c_signer_pk = ec_match(c->records, "_sign", 0, (unsigned char*)"key", 0, NULL, 0);
    if(!signer_pk || !c_signer_pk)
      return EC_ENOPUBLIC;
    if(signer_pk->data_len != c_signer_pk->data_len)
      return EC_ESIZE;
    if(memcmp(signer_pk->data, c_signer_pk->data, signer_pk->data_len))
      return EC_ECHAIN;

    //signer must also have a valid chain and pass all the checks that the current
    //cert is being tested for, except EC_CHECK_SECRET
    rfail(ec_check(c->signer, checks & ~EC_CHECK_SECRET));
  }

  //roles & grants
  if(checks & EC_CHECK_ROLE) {

    //iterate grants
    for(ec_record_t *r = ec_match(c->records, "_grant", 0, NULL, 0, NULL, 0); r && !(r->flags & EC_RECORD_SECTION); r = r->next) {

      //grants must have a valid string key
      if(!isstr(r->key, r->key_len))
        return EC_ERECORD;

      //grants must be granted in turn by the signer unless the cert is a trusted root
      if(!(c->flags & EC_CERT_TRUSTED) && ec_role_has_grant(c->signer, (char*)r->key))
        return EC_EGRANT;
    }

    //iterate roles
    for(ec_record_t *r = ec_match(c->records, "_role", 0, NULL, 0, NULL, 0); r && !(r->flags & EC_RECORD_SECTION); r = r->next) {

      //roles must have a valid string key
      if(!isstr(r->key, r->key_len))
        return EC_ETYPE;

      //roles must be granted by the signer unless the cert is a trusted root
      if(!(c->flags & EC_CERT_TRUSTED) && ec_role_has_grant(c->signer, (char*)r->key))
        return EC_EGRANT;
    }
  }

  //all tests passed
  return EC_OK;
}

/**
 * Tests whether two certificates are equal, based on their signable properties
 */
ec_err_t ec_certcmp(ec_cert_t *c1, ec_cert_t *c2) {
  if(c1 == c2)
    return EC_ESELF;
  unsigned char h1[EC_METHOD_BLAKE2B_512_BYTES];
  unsigned char h2[EC_METHOD_BLAKE2B_512_BYTES];
  rfail(ec_method_blake2b_512_hash(h1, c1));
  rfail(ec_method_blake2b_512_hash(h2, c2));
  return memcmp(h1, h2, EC_METHOD_BLAKE2B_512_BYTES) ? EC_EOK : EC_ESELF;
}

/**
 * Free a certificate
 */
void ec_cert_destroy(ec_cert_t *c) {
  ec_record_t *n = c->records;
  for(ec_record_t *r = n; r; r = n) {
    n = r->next;
    ec_record_destroy(r);
  }
  free(c);
}

/**
 * Generate a signing hash for BLAKE2B_512
 */
ec_err_t ec_method_blake2b_512_hash(unsigned char hash[EC_METHOD_BLAKE2B_512_BYTES], ec_cert_t *c) {
  //sanity checks
  if(!c->records)
    return EC_EMISSING;
  ec_assert(EC_METHOD_BLAKE2B_512_BYTES >= crypto_generichash_BYTES_MIN, EC_ESIZE, NULL);
  ec_assert(EC_METHOD_BLAKE2B_512_BYTES <= crypto_generichash_BYTES_MAX, EC_ESIZE, NULL);

  uint8_t export_cert_flags = c->flags & 0xFF;

  //init hash
  crypto_generichash_state state;
  crypto_generichash_init(&state, NULL, 0, EC_METHOD_BLAKE2B_512_BYTES);
  crypto_generichash_update(&state, (unsigned char*)&c->version, sizeof(c->version));
  crypto_generichash_update(&state, (unsigned char*)&export_cert_flags, sizeof(export_cert_flags));

  //records
  for(ec_record_t *r = c->records; r; r = r->next) {
    if(r->flags & EC_RECORD_NOSIGN)
      continue;
    uint8_t export_flags = r->flags & 0xFF;
    crypto_generichash_update(&state, (unsigned char*)&export_flags, sizeof(export_flags));
    crypto_generichash_update(&state, (unsigned char*)&r->key_len, sizeof(r->key_len));
    crypto_generichash_update(&state, r->key, r->key_len);
    crypto_generichash_update(&state, (unsigned char*)&r->data_len, sizeof(r->data_len));
    crypto_generichash_update(&state, r->data, r->data_len);
  }

  //finalise
  crypto_generichash_final(&state, hash, EC_METHOD_BLAKE2B_512_BYTES);
  return EC_OK;
}
