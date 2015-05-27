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
#include <talloc.h>

#define EC_EXPORT_LINE 72

static unsigned char *_bite(unsigned char **src, size_t *length, size_t bytes);

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
  size_t length = sizeof(uint8_t) * 2 //layout version, cert flags
    + sizeof(uint16_t) //exported cert length
    + sizeof(uint32_t) * 2 //validity period
    + sizeof(uint8_t); //NULL terminator
  ec_record_t *sk = ec_record_match(ec_cert_records(c), "_cert", 0, "sk", NULL, 0);
  ec_record_t *salt = ec_record_match(ec_cert_records(c), "_cert", 0, "salt", NULL, 0);
  for(ec_record_t *r = c->records; r; r = r->next) {
    if(!(export_flags & EC_EXPORT_SECRET) && (r == sk || r == salt))
      continue;
    length += ec_record_len(r); //records
  }
  return length <= EC_EXPORT_MAX ? length : 0;
}

/**
 * Export cert to buffer
 */
size_t ec_export(unsigned char *dest, ec_cert_t *c, uint8_t export_flags) {
  uint16_t length = ec_export_len(c, export_flags);
  if(!length)
    return 0;

  *dest++ = c->version;
  memcpy(dest, &length, sizeof(length)); dest += sizeof(length);
  *dest++ = c->flags;
  memcpy(dest, &c->valid_from, sizeof(c->valid_from)); dest += sizeof(c->valid_from);
  memcpy(dest, &c->valid_until, sizeof(c->valid_until)); dest += sizeof(c->valid_until);
  ec_record_t *sk = ec_record_match(ec_cert_records(c), "_cert", 0, "sk", NULL, 0);
  ec_record_t *salt = ec_record_match(ec_cert_records(c), "_cert", 0, "salt", NULL, 0);
  for(ec_record_t *r = c->records; r; r = r->next) {
    if(!(export_flags & EC_EXPORT_SECRET) && (r == sk || r == salt))
      continue;
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
 * Return current pointer, and seek buffer & length
 */
static unsigned char *_bite(unsigned char **src, size_t *length, size_t bytes) {
  unsigned char *p = *src;
  *length -= bytes;
  *src += bytes;
  return p;
}

/**
 * Import cert from buffer
 */
ec_cert_t *ec_import(unsigned char *src, size_t length, size_t *consumed) {
  if(consumed)
    *consumed = length;
  if(length < EC_EXPORT_MIN || (uint8_t)*src != EC_LAYOUT_VERSION)
    return NULL;
  ec_cert_t *c = talloc_zero(NULL, ec_cert_t);
  if(!c)
    return NULL;

  //layout version & cert exported length
  c->version = *_bite(&src, &length, sizeof(c->version));
  uint16_t export_length = 0;
  memcpy(&export_length, _bite(&src, &length, sizeof(export_length)), sizeof(export_length));
  if(export_length > length + sizeof(c->version) + sizeof(export_length))  {
    free(c);
    return NULL;
  }
  else
    length = export_length - sizeof(c->version) - sizeof(export_length);

  //flags & export flags
  c->flags = *_bite(&src, &length, sizeof(c->flags));

  //validity period
  memcpy(&c->valid_from, _bite(&src, &length, sizeof(c->valid_from)), sizeof(c->valid_from));
  memcpy(&c->valid_until, _bite(&src, &length, sizeof(c->valid_until)), sizeof(c->valid_until));

  //records
  for(ec_record_t **r = &c->records; length > EC_RECORD_MIN + sizeof(uint8_t); r = &(*r)->next) {
    uint16_t record_length = 0;
    memcpy(&record_length, _bite(&src, &length, sizeof(record_length)), sizeof(record_length));
    if(record_length >= length + sizeof(record_length))
      break;

    if(!((*r) = talloc_zero(c, ec_record_t))) {
      ec_cert_destroy(c);
      ec_err_r(ENOMEM, NULL);
    }
    (*r)->flags = *_bite(&src, &length, sizeof(uint8_t));
    (*r)->key_len = *_bite(&src, &length, sizeof((*r)->key_len));
    (*r)->data_len = record_length - EC_RECORD_MIN - (*r)->key_len;
    (*r)->key = talloc_memdup(*r, _bite(&src, &length, (*r)->key_len), (*r)->key_len);
    (*r)->data = talloc_memdup(*r, _bite(&src, &length, (*r)->data_len), (*r)->data_len);
    if(!(*r)->key || !(*r)->data) {
      ec_cert_destroy(c);
      ec_err_r(ENOMEM, NULL);
    }
  }

  //field buffers
  c->pk = ec_record_buf(c, "_cert", "pk", crypto_sign_PUBLICKEYBYTES, EC_RECORD_SIGNED);
  c->sk = ec_record_buf(c, "_cert", "sk", crypto_sign_SECRETKEYBYTES, 0);
  if(c->sk)
    sodium_mlock(c->sk, crypto_sign_SECRETKEYBYTES);
  c->salt = ec_record_buf(c, "_cert", "salt", crypto_pwhash_scryptsalsa208sha256_SALTBYTES, 0);
  c->signer_id = ec_record_buf(c, "_cert", "signer_id", EC_CERT_ID_BYTES, EC_RECORD_SIGNED);
  c->signature = ec_record_buf(c, "_cert", "signature", crypto_sign_BYTES, 0);

  //NULL terminator && no remaining data && cert passes basic checks
  if(*_bite(&src, &length, sizeof(uint8_t)) || length || ec_cert_check(NULL, c, EC_CHECK_CERT)) {
    ec_cert_destroy(c);
    return NULL;
  }

  if(consumed)
    *consumed -= length;
  return c;
}

/**
 * Get the required buffer length to export a certificate to base64
 */
size_t ec_export_len_64(ec_cert_t *c, uint8_t export_flags) {
  size_t length = ec_export_len(c, export_flags);
  if(!length)
    return 0;
  length = ec_base64_len(length);
  length +=
    (length / EC_EXPORT_LINE) + ((length % EC_EXPORT_LINE) ? 1 : 0) //split into lines
    + strlent(EC_EXPORT_BEGIN) + strlent(EC_EXPORT_END) //envelope
    + 1; //trailing NULL
  return length;
}

/**
 * Export a certificate to base64
 */
char *ec_export_64(char *dest, ec_cert_t *c, uint8_t export_flags) {
  size_t length = ec_export_len(c, export_flags);
  if(!length)
    return NULL;
  unsigned char buf[length];
  if(!ec_export(buf, c, export_flags))
    return NULL;
  char *pos = dest;
  strcpy(pos, EC_EXPORT_BEGIN);
  while(*pos++);
  pos[-1] = '\n';
  const int line_bin = EC_EXPORT_LINE * 3 / 4;
  for(int i = 0; i < length; i += line_bin) {
    int chunk = (length - i > line_bin) ? line_bin : length - i;
    pos += ec_base64_encode(pos, &buf[i], chunk);
    *pos++ = '\n';
  }
  strcpy(pos, EC_EXPORT_END);
  strcat(pos, "\n");
  return dest;
}

/**
 * Import a cert from base64
 */
ec_cert_t *ec_import_64(char *src, size_t length, size_t *consumed) {
  const int binary_line = EC_EXPORT_LINE * 3 / 4;

  //basic sanity check on length
  const int min_length =
    strlent(EC_EXPORT_BEGIN) + strlent(EC_EXPORT_END)
    + ec_base64_len(EC_EXPORT_MIN);
  if(length < min_length)
    return NULL;

  //copy src & convert newlines to nulls
  char sbuf[length];
  memcpy(sbuf, src, length);
  sbuf[length-1] = '\0';
  for(int i = 0; i < length; i++) {
    if(sbuf[i] == '\n')
      sbuf[i] = '\0';
  }

  unsigned char buf[length];
  unsigned char *pos = buf;
  int in_cert = 0;

  //find certificate portion of text and decode into buf
  if(consumed)
    *consumed = 0;
  for(char *line = sbuf; line - sbuf < length; line += strlent(line)) {
    if(consumed)
      *consumed += strlent(line);
    if(!in_cert && !strcmp(line, EC_EXPORT_BEGIN))
      in_cert = 1;
    else if(in_cert) {
      if(!strcmp(line, EC_EXPORT_END)) {
        in_cert = 0;
        break;
      }
      ec_base64_decode(pos, line, strlen(line));
      pos += binary_line;
    }
  }

  //no ending block found
  if(in_cert)
    return NULL;

  return ec_import(buf, sizeof(buf), NULL);
}
