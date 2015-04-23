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
#include <string.h>

/**
 * Get the export length for a certificate
 */
size_t ec_export_len(ec_cert_t *c, int flags) {
  size_t len = sizeof(c->version) //version
    + sizeof(uint8_t) //flags
    + sizeof(uint16_t) //cert length
    + sizeof(char); //terminating NULL

  char *section = "";
  //iterate records
  for(ec_record_t *r = c->records; r; r = r->next) {
    //get current section
    if(r->flags & EC_RECORD_SECTION) {
      assert(isstr(r->key, r->key_len), EC_ETYPE, NULL);
      section = (char*)r->key;
    }
    //don't export secret section unless EC_EXPORT_SECRET is set
    if(!(flags & EC_EXPORT_SECRET) && !strcmp(section, "_secret"))
      continue;

    //add record to length
    len += sizeof(uint16_t) //record length
      + sizeof(uint8_t) //key length
      + sizeof(uint8_t) //flags
      + r->key_len // key
      + r->data_len; //data
  }

  //add chain
  if((flags & EC_EXPORT_CHAIN) && c->signer && !ec_certcmp(c, c->signer)
    && ((flags & EC_EXPORT_ROOT) || !(c->signer->flags & EC_CERT_TRUSTED)))
    len += ec_export_len(c->signer, flags & ~EC_EXPORT_SECRET);

  return len;
}

/**
 * Export a certificate
 */
ec_err_t ec_export(unsigned char *dest, ec_cert_t *c, int flags) {
  //ensure certificate is sane
  rfail(ec_check(c, EC_CHECK_CERT));

  unsigned char *buf = dest;
  uint8_t export_flags = c->flags & 0xFF;
  //version & flags
  memcpy(buf, &c->version, sizeof(c->version)); buf += sizeof(c->version);
  memcpy(buf, &export_flags, sizeof(export_flags)); buf += sizeof(export_flags);

  //length
  size_t cert_len = ec_export_len(c, flags & ~EC_EXPORT_CHAIN);
  if(cert_len > EC_EXPORT_MAX)
    return EC_ESIZE;
  memcpy(buf, &cert_len, sizeof(uint16_t)); buf += sizeof(uint16_t);

  char *section = "";
  //iterate records
  for(ec_record_t *r = c->records; r; r = r->next) {
    //get current section
    if(r->flags & EC_RECORD_SECTION) {
      assert(isstr(r->key, r->key_len), EC_ETYPE, NULL);
      section = (char*)r->key;
    }

    //don't export secret section unless EC_EXPORT_SECRET is set
    if(!(flags & EC_EXPORT_SECRET) && !strcmp(section, "_secret"))
      continue;

    //export record
    uint8_t export_flags = r->flags & 0xFF;
    uint16_t record_len = sizeof(record_len) //record length
      + sizeof(r->key_len) //key length
      + sizeof(export_flags) //flags
      + r->key_len //key
      + r->data_len; //data
    memcpy(buf, &record_len, sizeof(record_len)); buf += sizeof(record_len);
    memcpy(buf, &r->key_len, sizeof(r->key_len)); buf += sizeof(r->key_len);
    memcpy(buf, &export_flags, sizeof(export_flags)); buf += sizeof(export_flags);
    memcpy(buf, r->key, r->key_len); buf += r->key_len;
    memcpy(buf, r->data, r->data_len); buf += r->data_len;
  }

  //terminating NULL
  *buf = '\0'; buf++;

  //chain
  if((flags & EC_EXPORT_CHAIN) && c->signer && !ec_certcmp(c, c->signer)
    && ((flags & EC_EXPORT_ROOT) || !(c->signer->flags & EC_CERT_TRUSTED)))
    return ec_export(buf, c->signer, flags & ~EC_EXPORT_SECRET);

  return EC_OK;
}

/**
 * Import a certificate
 */
ec_cert_t *ec_import(unsigned char *src, size_t src_len, int flags) {
  //sanity check - src must be long enough, and must be a NULL-terminated string
  if(src_len <= EC_EXPORT_MIN)
    return NULL;
  if(!isstr(src, src_len))
    return NULL;

  //create empty cert object
  unsigned char *buf = src;
  ec_cert_t *c = calloc(1, sizeof(*c));
  assert(c, EC_ENOMEM, NULL);
  
  //version & flags
  memcpy(&c->version, buf, sizeof(c->version)); buf += sizeof(c->version);
  memcpy(&c->flags, buf, sizeof(uint8_t)); buf += sizeof(uint8_t);

  //cert length
  size_t cert_len = 0;
  memcpy(&cert_len, buf, sizeof(uint16_t)); buf += sizeof(uint16_t);
  if(src_len < cert_len - (buf - src)) {
    ec_cert_destroy(c);
    return NULL;
  }

  //records
  ec_record_t **r = &c->records;
  while(cert_len - (buf - src) > EC_RECORD_MIN) {
    //record length
    size_t record_len = 0;
    memcpy(&record_len, buf, sizeof(uint16_t)); buf += sizeof(uint16_t);
    if(record_len - sizeof(uint16_t) > src_len - (buf - src)) { //record must fit into remaining buffer
      ec_cert_destroy(c);
      return NULL;
    }
    //create record & set key_len, flags, data_len
    assert(*r = calloc(1, sizeof(**r)), EC_ENOMEM, NULL);
    memcpy(&(*r)->key_len, buf, sizeof((*r)->key_len)); buf += sizeof((*r)->key_len);
    memcpy(&(*r)->flags, buf, sizeof(uint8_t)); buf += sizeof(uint8_t);
    (*r)->data_len = record_len - (*r)->key_len - EC_RECORD_OVERHEAD;
    if((*r)->data_len + (*r)->key_len > src_len - (buf - src)) { //record key + data must fit into remaining buffer
      ec_cert_destroy(c);
      return NULL;
    }
    //key
    if((*r)->key_len) {
      (*r)->flags |= EC_RECORD_KFREE;
      assert((*r)->key = calloc(1, (*r)->key_len), EC_ENOMEM, NULL);
      memcpy((*r)->key, buf, (*r)->key_len); buf += (*r)->key_len;
    }
    //data
    if((*r)->data_len) {
      (*r)->flags |= EC_RECORD_DFREE;
      assert((*r)->data = calloc(1, (*r)->data_len), EC_ENOMEM, NULL);
      memcpy((*r)->data, buf, (*r)->data_len); buf += (*r)->data_len;
    }
    r = &(*r)->next;
  }

  //check imported cert & NULL terminator
  if(*buf++ || ec_check(c, EC_CHECK_CERT)) {
    ec_cert_destroy(c);
    return NULL;
  }

  //import chain
  if(flags & EC_IMPORT_CHAIN)
    c->signer = ec_import(buf, src_len - (buf - src), flags);

  return c;
}
