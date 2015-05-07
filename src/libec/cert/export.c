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
#include <string.h>
#include <malloc.h>
#include <sodium.h>

/**
 * Get the required buffer length to export a record
 */
static size_t ec_record_len(ec_record_t *r) {
  return EC_RECORD_MIN //record length, flags & key length
    + r->key_len //key
    + r->data_len; //data
}

/**
 * Get the required buffer length to export a certificate
 */
uint16_t ec_export_len(ec_cert_t *c, uint8_t export_flags) {
  size_t length = sizeof(uint8_t) * 3 //layout version, cert flags, export flags
    + sizeof(uint16_t) //exported cert length
    + sizeof(uint32_t) * 2 //validity period
    + crypto_sign_PUBLICKEYBYTES //pk
    + (c->signer_id ? EC_CERT_ID_BYTES : 0) //signer id
    + (c->signature ? crypto_sign_BYTES : 0) //signature
    + ((c->sk && (export_flags & EC_EXPORT_SECRET)) ? crypto_sign_SECRETKEYBYTES : 0) //sk
    + sizeof(uint8_t); //NULL terminator
  for(ec_record_t *r = c->records; r; r = r->next)
    length += ec_record_len(r); //records
  return length <= EC_EXPORT_MAX ? length : 0;
}

/**
 * Export cert to buffer
 */
size_t ec_export(unsigned char *dest, ec_cert_t *c, uint8_t export_flags) {
  uint16_t length = ec_export_len(c, export_flags);
  if(!length)
    return 0;
  if(!c->sk)
    export_flags &= ~EC_EXPORT_SECRET;
  if(c->signer_id)
    export_flags |= EC_EXPORT_SIGNER;
  if(c->signature)
    export_flags |= EC_EXPORT_SIGNATURE;

  *dest++ = c->version;
  memcpy(dest, &length, sizeof(length)); dest += sizeof(length);
  *dest++ = c->flags;
  *dest++ = export_flags;
  memcpy(dest, &c->valid_from, sizeof(c->valid_from)); dest += sizeof(c->valid_from);
  memcpy(dest, &c->valid_until, sizeof(c->valid_until)); dest += sizeof(c->valid_until);
  memcpy(dest, c->pk, crypto_sign_PUBLICKEYBYTES), dest += crypto_sign_PUBLICKEYBYTES;
  if(c->signer_id) {
    memcpy(dest, c->signer_id, EC_CERT_ID_BYTES);
    dest += EC_CERT_ID_BYTES;
  }
  if(c->signature) {
    memcpy(dest, c->signature, crypto_sign_BYTES);
    dest += crypto_sign_BYTES;
  }
  if(c->sk && (export_flags & EC_EXPORT_SECRET)) {
    memcpy(dest, c->sk, crypto_sign_SECRETKEYBYTES);
    dest += crypto_sign_SECRETKEYBYTES;
  }
  for(ec_record_t *r = c->records; r; r = r->next) {
    uint16_t length = ec_record_len(r);
    memcpy(dest, &length, sizeof(length)); dest += sizeof(length);
    *dest++ = r->flags;
    *dest++ = r->key_len;
    memcpy(dest, r->key, r->key_len); dest += r->key_len;
    memcpy(dest, r->data, r->data_len); dest += r->data_len;
  }
  *dest = '\0';
  return length;
}

/**
 * Import cert from buffer
 */
ec_cert_t *ec_import(unsigned char *src, size_t length) {
  unsigned char *bite(size_t bytes) {
    unsigned char *p = src;
    length -= bytes;
    src += bytes;
    return p;
  }
  if(length < EC_EXPORT_MIN || (uint8_t)*src != EC_LAYOUT_VERSION)
    return NULL;
  ec_cert_t *c = calloc(1, sizeof(*c));
  if(!c)
    return NULL;


  //layout version & cert exported length
  c->version = *bite(sizeof(c->version));
  uint16_t export_length = 0;
  memcpy(&export_length, bite(sizeof(export_length)), sizeof(export_length));
  if(export_length > length + sizeof(c->version) + sizeof(export_length))  {
    free(c);
    return NULL;
  }
  else
    length = export_length - sizeof(c->version) - sizeof(export_length);

  //flags & export flags
  c->flags = *bite(sizeof(c->flags));
  uint8_t export_flags = *bite(sizeof(export_flags));

  //validity period
  memcpy(&c->valid_from, bite(sizeof(c->valid_from)), sizeof(c->valid_from));
  memcpy(&c->valid_until, bite(sizeof(c->valid_until)), sizeof(c->valid_until));

  //pk
  if(length < crypto_sign_PUBLICKEYBYTES || !(c->pk = fmalloc(crypto_sign_PUBLICKEYBYTES, c)))
    return NULL;
  memcpy(c->pk, bite(crypto_sign_PUBLICKEYBYTES), crypto_sign_PUBLICKEYBYTES);

  //signer
  if(export_flags & EC_EXPORT_SIGNER) {
    if(length < EC_CERT_ID_BYTES || !(c->signer_id = fmalloc(EC_CERT_ID_BYTES, c->pk, c)))
      return NULL;
    memcpy(c->signer_id, bite(EC_CERT_ID_BYTES), EC_CERT_ID_BYTES);
  }

  //signature
  if(export_flags & EC_EXPORT_SIGNATURE) {
    if(length < crypto_sign_BYTES || !(c->signature = fmalloc(crypto_sign_BYTES, c->signer_id, c->pk, c)))
      return NULL;
    memcpy(c->signature, bite(crypto_sign_BYTES), crypto_sign_BYTES);
  }

  //sk
  if(export_flags & EC_EXPORT_SECRET) {
    if(length < crypto_sign_SECRETKEYBYTES || !(c->sk = fmalloc(crypto_sign_SECRETKEYBYTES,
      c->signature, c->signer_id, c->pk, c)))
    {
      return NULL;
    }
    memcpy(c->sk, bite(crypto_sign_SECRETKEYBYTES), crypto_sign_SECRETKEYBYTES);
  }

  //records
  for(ec_record_t **r = &c->records; length > EC_RECORD_MIN + sizeof(uint8_t); r = &(*r)->next) {
    uint16_t record_length = 0;
    memcpy(&record_length, bite(sizeof(record_length)), sizeof(record_length));
    if(record_length >= length + sizeof(record_length))
      break;
    if(!((*r) = calloc(1, sizeof(**r) + record_length - EC_RECORD_MIN)))
      break;
    (*r)->flags = *bite(sizeof(uint8_t));
    (*r)->key_len = *bite(sizeof((*r)->key_len));
    (*r)->data_len = record_length - EC_RECORD_MIN - (*r)->key_len;
    (*r)->key = (unsigned char*)((*r) + 1);
    memcpy((*r)->key, bite((*r)->key_len), (*r)->key_len);
    (*r)->data = (*r)->key + (*r)->key_len;
    memcpy((*r)->data, bite((*r)->data_len), (*r)->data_len);
  }

  //NULL terminator && no remaining data && cert passes basic checks
  if(*bite(sizeof(uint8_t)) || length || ec_cert_check(NULL, c, EC_CHECK_CERT)) {
    ec_cert_destroy(c);
    return NULL;
  }

  return c;
}
