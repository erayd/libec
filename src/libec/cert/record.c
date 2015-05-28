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
#include <talloc.h>

static int _talloc_destructor(ec_record_t *ptr);

/**
 * Talloc destructor
 */
static int _talloc_destructor(ec_record_t *ptr) {
  ec_record_destroy(ptr);
  return 0;
}

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
  ec_record_t *r = talloc_zero(NULL, ec_record_t);
  if(!r)
    ec_err_r(ENOMEM, NULL);
  r->key_len = key_len;
  if(flags & EC_RECORD_KCOPY) {
    flags &= ~EC_RECORD_KFREE;
    if(!(r->key = talloc_memdup(r, key, key_len))) {
      talloc_free(r);
      ec_err_r(ENOMEM, NULL);
    }
  }
  else if(flags & EC_RECORD_KALLOC) {
    if(!(r->key = talloc_zero_size(r, key_len))) {
      talloc_free(r);
      ec_err_r(ENOMEM, NULL);
    }
  }
  else
    r->key = key;
  r->data_len = data_len;
  if(flags & EC_RECORD_DCOPY) {
    flags &= ~EC_RECORD_DFREE;
    if(!(r->data = talloc_memdup(r, data, data_len))) {
      talloc_free(r);
      ec_err_r(ENOMEM, NULL);
    }
  }
  else if (flags & EC_RECORD_DALLOC) {
    if(!(r->data = talloc_zero_size(r, data_len))) {
      talloc_free(r);
      ec_err_r(ENOMEM, NULL);
    }
  }
  else
    r->data = data;
  r->flags = flags;

  //clean up on talloc free
  talloc_set_destructor(r, _talloc_destructor);

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
ec_record_t *ec_record_create(uint16_t flags, char *key, unsigned char *data, uint16_t data_len) {
  return ec_record_bin(flags, (unsigned char*)key, 0, data, data_len);
}

/**
 * Append a record to a list
 */
ec_record_t *ec_record_add(ec_cert_t *c, char *section, ec_record_t *r) {
  //sanity check
  if(!r)
    return NULL;

  //change talloc context
  talloc_reparent(talloc_parent(r), c, r);

  //provided record is a section record
  if(r->flags & EC_RECORD_SECTION) {
    r->next = c->records;
    return c->records = r;
  }

  ec_record_t *s = ec_record_match(ec_cert_records(c), NULL, EC_RECORD_SECTION, section, NULL, 0);
  //create section if missing
  if(!s) {
    if(!(s = ec_record_create(EC_RECORD_SECTION|EC_RECORD_KCOPY, section, NULL, 0)))
      ec_err_r(ENOMEM, NULL);
    talloc_reparent(talloc_parent(s), c, s);
    s->next = ec_cert_records(c);
    c->records = s;
  }

  //append record to section
  r->section = s;
  r->next = s->next;
  s->next = r;

  //inherit flags from section
  r->flags |= (s->flags & EC_RECORD_NOSIGN);
  if((s->flags | r->flags) & EC_RECORD_INHERIT)
    r->flags |= ((s->flags & ~EC_RECORD_SECTION) & 0xFF);

  return r;
}

/**
 * Remove a record from a certificate
 */
ec_record_t *ec_record_remove(ec_cert_t *c, ec_record_t *r) {
  if(!r)
    return NULL;
  for(ec_record_t **p = &c->records; *p; p = &(*p)->next) {
    if(*p == r) {
      talloc_reparent(talloc_parent(*p), NULL, *p);
      *p = (*p)->next;
      break;
    }
  }
  return r;
}

/**
 * Remove an entire section from a certificate
 */
void ec_record_remove_section(ec_cert_t *c, char *section, ec_freefn_t freefn) {
  ec_record_t *s = ec_record_match(ec_cert_records(c), NULL, EC_RECORD_SECTION, section, NULL, 0);
  if(s) {
    ec_record_t *next = s->next;
    for(ec_record_t *r = next; r; r = next) {
      if(r->flags & EC_RECORD_SECTION)
        break;
      s->next = next = r->next;
      talloc_reparent(talloc_parent(r), NULL, r);
      if(freefn)
        freefn(r);
    }
    s->next = next;
    ec_record_destroy(ec_record_remove(c, s));
  }
}

/**
 * Find the first matching record in a record list using binary key & data
 */
ec_record_t *ec_record_match_bin(ec_record_t *start, char *section, uint16_t flags, unsigned char *key,
  uint8_t key_len, unsigned char *data, uint16_t data_len)
{
  //sanity check
  if(!start)
    return NULL;

  //process string input
  if(!key_len && key)
    key_len = strlent(key);
  if(!data_len && data)
    data_len = strlent(data);

  //if section isn't defined, look for a section header
  if(!section)
    flags |= EC_RECORD_SECTION;

  //find section header
  if(section && (start = ec_record_match(start, NULL, EC_RECORD_SECTION, section, NULL, 0)))
    start = start->next;

  //search records
  for(ec_record_t *r = start; r; r = r->next) {
    //stop searching on section boundary
    if((r->flags & EC_RECORD_SECTION) && !(flags & EC_RECORD_SECTION))
      break;
    //flags
    if(flags) {
      if((r->flags & flags) != flags)
        continue;
      if((flags & EC_RECORD_SIGNED) && (r->flags & EC_RECORD_NOSIGN))
        continue;
    }
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
ec_record_t *ec_record_match_str(ec_record_t *start, char *section, uint16_t flags, char *key, char *data) {
  return ec_record_match_bin(start, section, flags, (unsigned char*)key, 0, (unsigned char*)data, 0);
}

/**
 * Find the first matching record in a record list using string key & binary data
 */
ec_record_t *ec_record_match(ec_record_t *start, char *section, uint16_t flags, char *key,
  unsigned char *data, uint16_t data_len)
{
  return ec_record_match_bin(start, section, flags, (unsigned char*)key, 0, data, data_len);
}

/**
 * Get the next matching record in the same section
 */
ec_record_t *ec_record_next(ec_record_t *start, int filter) {
  if(!start)
    return NULL;
  if(filter & EC_MATCH_KEY)
    filter |= EC_MATCH_KEY_LEN;
  if(filter & EC_MATCH_DATA)
    filter |= EC_MATCH_DATA_LEN;

  for(ec_record_t *r = start->next; r; r = r->next) {
    if(r->flags & EC_RECORD_SECTION)
      return NULL;

    if(filter & EC_MATCH_FLAGS) {
      if(((r->flags & start->flags) & 0xFF) != (start->flags & 0xFF))
        continue;
    }
    if((filter & EC_MATCH_KEY_LEN) && r->key_len != start->key_len)
      continue;
    if((filter & EC_MATCH_DATA_LEN) && r->data_len != start->data_len)
      continue;
    if((filter & EC_MATCH_KEY) && memcmp(r->key, start->key, start->key_len))
      continue;
    if((filter & EC_MATCH_DATA) && memcmp(r->data, start->data, start->data_len))
      continue;
    return r;
  }
  return NULL;
}

/**
 * Set a string record
 */
ec_record_t *ec_record_set(ec_cert_t *c, char *section, uint16_t flags, char *key, char *data) {
  return ec_record_add(c, section, ec_record_str(flags, key, data));
}

/**
 * Get the string data for a record with matching key / flags.
 */
char *ec_record_get(ec_record_t *start, char *section, uint16_t flags, char *key) {
  ec_record_t *r = ec_record_match(start, section, flags, key, NULL, 0);
  if(r && isstr(r->data, r->data_len))
    return (char*)r->data;
  return NULL;
}

/**
 * Get the section for a record
 */
char *ec_record_section(ec_record_t *r) {
  return r->section ? (char*)r->section->key : NULL;
}

/**
 * Get the data buffer for a record
 */
unsigned char *ec_record_data(ec_record_t *r) {
  return r ? r->data : NULL;
}

/**
 * Free a record, plus associated data if KFREE / DFREE is set
 */
void ec_record_destroy(ec_record_t *r) {
  if(!r)
    return;
  if(r->flags & EC_RECORD_KFREE)
    free(r->key);
  if(r->flags & EC_RECORD_DFREE)
    free(r->data);
  talloc_free(r);
}

/**
 * Get or create a data buffer at least $length bytes long in a record
 */
unsigned char *ec_record_buf(ec_cert_t *c, char *section, char *key, size_t length, uint16_t flags) {
  ec_record_t *r = ec_record_match(ec_cert_records(c), section, 0, key, NULL, 0);
  //record exists
  if(r) {
    if((r->flags & (flags & 0xFF)) != (flags & 0xFF))
      return NULL;
    if((r->flags & EC_RECORD_NOSIGN) && (flags & EC_RECORD_SIGNED))
      return NULL;
    if(!r->data || (length && r->data_len < length))
      return NULL;
    return r->data;
  }
  //create record
  r = ec_record_add(c, section, ec_record_create(EC_RECORD_KCOPY | EC_RECORD_DALLOC, key, NULL, length));
  if(!r)
    return NULL;
  r->flags |= (flags & 0xFF);
  return r->data;
}

/**
 * Bulk-set additional flags for an entire section
 */
void ec_record_section_flags(ec_cert_t *c, char *section, uint16_t flags) {
  ec_record_t *s = ec_record_match(ec_cert_records(c), NULL, EC_RECORD_SECTION, section, NULL, 0);
  if(s) {
    flags &= 0xFF;
    s->flags |= flags;
    for(ec_record_t *r = s->next; r && !(r->flags & EC_RECORD_SECTION); r = r->next)
      r->flags |= flags;
  }
}
