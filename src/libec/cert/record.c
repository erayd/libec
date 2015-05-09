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

/**
 * Create a new record with binary key & data
 */
ec_record_t *ec_record_bin(uint16_t flags, unsigned char *key, uint8_t key_len, unsigned char *data, uint16_t data_len) {
  //process string input
  if(!key_len && key)
    key_len = strlent(key);
  if(!data_len && data)
    data_len = strlent(data);

  //sanitise data length
  if(data_len > EC_RECORD_DMAX)
    data_len = EC_RECORD_DMAX;

  //build record
  ec_record_t *r = calloc(1, sizeof(*r));
  if(!r)
    ec_err_r(ENOMEM, NULL, NULL);
  r->key_len = key_len;
  if(flags & EC_RECORD_KCOPY) {
    flags |= EC_RECORD_KFREE;
    if(!(r->key = fcalloc(key_len, r)))
      ec_err_r(ENOMEM, NULL, NULL);
    memcpy(r->key, key, key_len);
  }
  else
    r->key = key;
  r->data_len = data_len;
  if(flags & EC_RECORD_DCOPY) {
    flags |= EC_RECORD_DFREE;
    if(!(r->data = fcalloc(data_len, r->key, r)))
      ec_err_r(ENOMEM, NULL, NULL);
    memcpy(r->data, data, data_len);
  }
  else
    r->data = data;
  r->flags = flags;

  return r;
}

/**
 * Create a new record with string key & data
 */
ec_record_t *ec_record_str(uint16_t flags, char *key, char *data) {
  return ec_record_bin(flags, (unsigned char*)key, 0, (unsigned char*)data, 0);
}

/**
 * Create a new record with a string key
 */
ec_record_t *ec_record(uint16_t flags, char *key, unsigned char *data, uint16_t data_len) {
  return ec_record_bin(flags, (unsigned char*)key, 0, data, data_len);
}

/**
 * Append a record to a list
 */
ec_record_t *ec_add(ec_cert_t *c, char *section, ec_record_t *r) {
  //sanity check
  if(!r)
    return NULL;

  //provided record is a section record
  if(r->flags & EC_RECORD_SECTION) {
    r->next = c->records;
    return c->records = r;
  }

  ec_record_t *s = ec_match(c->records, NULL, EC_RECORD_SECTION, section, NULL, 0);
  //create section if missing
  if(!s) {
    if(!(s = ec_record(EC_RECORD_SECTION|EC_RECORD_KCOPY, section, NULL, 0)))
      ec_err_r(ENOMEM, NULL, NULL);
    s->next = c->records;
    c->records = s;
  }
  //append record to section
  r->next = s->next;
  s->next = r;

  //inherit flags from section
  if((s->flags | r->flags) & EC_RECORD_INHERIT)
    r->flags |= ((s->flags & ~EC_RECORD_SECTION) & 0xFF);

  return r;
}

/**
 * Find the first matching record in a record list using binary key & data
 */
ec_record_t *ec_match_bin(ec_record_t *start, char *section, uint16_t flags, unsigned char *key, uint8_t key_len,
  unsigned char *data, uint16_t data_len)
{
  //process string input
  if(!key_len && key)
    key_len = strlent(key);
  if(!data_len && data)
    data_len = strlent(data);

  //if section isn't defined, look for a section header
  if(!section)
    flags |= EC_RECORD_SECTION;

  //find section header
  if(section && (start = ec_match(start, NULL, EC_RECORD_SECTION, section, NULL, 0)))
    start = start->next;

  //search records
  for(ec_record_t *r = start; r; r = r->next) {
    //stop searching on section boundary
    if((r->flags & EC_RECORD_SECTION) && !(flags & EC_RECORD_SECTION))
      break;
    //flags
    if(flags && (r->flags & flags) != flags)
      continue;
    //key
    if(key_len) {
      if(r->key_len != key_len)
        continue;
      if(key && memcmp(r->key, key, key_len))
        continue;
    }
    //data
    if(data_len) {
      if(r->data_len != data_len)
        continue;
      if(data && memcmp(r->data, data, data_len))
        continue;
    }
    return r;
  }
  return NULL;
}

/**
 * Find the first matching record in a record list using string key & data
 */
ec_record_t *ec_match_str(ec_record_t *start, char *section, uint16_t flags, char *key, char *data) {
  return ec_match_bin(start, section, flags, (unsigned char*)key, 0, (unsigned char*)data, 0);
}

/**
 * Find the first matching record in a record list using string key & binary data
 */
ec_record_t *ec_match(ec_record_t *start, char *section, uint16_t flags, char *key, unsigned char *data,
  uint16_t data_len)
{
  return ec_match_bin(start, section, flags, (unsigned char*)key, 0, data, data_len);
}

/**
 * Set a string record
 */
ec_record_t *ec_set(ec_cert_t *c, char *section, uint16_t flags, char *key, char *data) {
  return ec_add(c, section, ec_record_str(flags, key, data));
}

/**
 * Get the string data for a record with matching key / flags.
 */
char *ec_get(ec_record_t *start, char *section, uint16_t flags, char *key) {
  ec_record_t *r = ec_match(start, section, flags, key, NULL, 0);
  if(r && isstr(r->data, r->data_len))
    return (char*)r->data;
  return NULL;
}

//free a record, plus associated data if KFREE / DFREE is set
void ec_record_destroy(ec_record_t *r);

/**
 * Free a record, plus associated data if KFREE / DFREE is set
 */
void ec_record_destroy(ec_record_t *r) {
  if(r->flags & EC_RECORD_KFREE)
    free(r->key);
  if(r->flags & EC_RECORD_DFREE)
    free(r->data);
  free(r);
}


