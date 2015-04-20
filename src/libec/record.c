/*
This file is part of libec (https://github.com/erayd/libec/).
Copyright (C) 2014 Erayd LTD. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
  * Neither the name of Erayd LTD nor the
    names of its contributors may be used to endorse or promote products
    derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL ERAYD LTD BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <common.h>
#include <string.h>
#include <malloc.h>

/**
 * Create a new record
 */
ec_record_t *ec_record(uint16_t flags, unsigned char *key, uint8_t key_len, unsigned char *data, uint16_t data_len) {
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
  assert(r, EC_ENOMEM, NULL);
  r->key_len = key_len;
  if(flags & EC_RECORD_KCOPY) {
    flags |= EC_RECORD_KFREE;
    assert(r->key = calloc(1, key_len), EC_ENOMEM, NULL);
    memcpy(r->key, key, key_len);
  }
  else
    r->key = key;
  r->data_len = data_len;
  if(flags & EC_RECORD_DCOPY) {
    flags |= EC_RECORD_DFREE;
    assert(r->data = calloc(1, data_len), EC_ENOMEM, NULL);
    memcpy(r->data, data, data_len);
  }
  else
    r->data = data;
  r->flags = flags;

  return r;
}

/**
 * Append a record to a list
 */
ec_record_t *ec_append(ec_cert_t *c, char *section, ec_record_t *r) {
  //provided record is a section record
  if(r->flags & EC_RECORD_SECTION) {
    r->next = c->records;
    return c->records = r;
  }

  ec_record_t *s = ec_match(c->records, NULL, EC_RECORD_SECTION, (unsigned char*)section, 0, NULL, 0);
  //create section if missing
  if(!s) {
    s = ec_record(EC_RECORD_SECTION|EC_RECORD_KCOPY, (unsigned char*)section, 0, NULL, 0);
    assert(s, EC_ENOMEM, NULL);
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
 * Find the first matching record in a list
 */
ec_record_t *ec_match(ec_record_t *start, char *section, uint16_t flags, unsigned char *key, uint8_t key_len, unsigned char *data, uint16_t data_len) {
  //process string input
  if(!key_len && key)
    key_len = strlent(key);
  if(!data_len && data)
    data_len = strlent(data);

  if(section && (start = ec_match(start, NULL, EC_RECORD_SECTION, (unsigned char*)section, 0, NULL, 0)))
    start = start->next;

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
 * Free a record
 */
void ec_record_destroy(ec_record_t *r) {
  if(r->flags & EC_RECORD_KFREE)
    free(r->key);
  if(r->flags & EC_RECORD_DFREE)
    free(r->data);
  free(r);
}


