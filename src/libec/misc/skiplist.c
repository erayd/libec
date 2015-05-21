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

/**
 * Create a skiplist
 */
ec_sl_t *ec_sl_create(ec_sl_compfn_t compfn) {
  ec_sl_t *l = talloc_zero(NULL, ec_sl_t);
  if(!l)
    ec_err_r(ENOMEM, NULL, NULL);
  l->compfn = compfn;
  return l;
}

/**
 * Destroy a skiplist
 */
void ec_sl_destroy(ec_sl_t *l, ec_sl_freefn_t freefn) {
  ec_sl_node_t *next = l->start[1].next;
  for(ec_sl_node_t *n = next; n; n = next) {
    next = n[1].next;
    if(freefn)
      freefn(n->data);
  }
  talloc_free(l);
}

/**
 * Get a cursor immediately before a given key, whether or not the key exists
 */
ec_sl_cursor_t *ec_sl_cursor(ec_sl_t *l, ec_sl_cursor_t *c, void *key) {
  ec_sl_node_t *n = l->start;

  //Set out-of-range nodes to l->start
  for(int level = EC_SL_MAXLEVEL; level > l->level; level--)
    (*c)[level] = &n[level];

  //Set in-range nodes
  for(int level = l->level; level; level--) {
    while(n[level].next && (!key || l->compfn(key, n[level].next->data) > 0))
      n = n[level].next;
    (*c)[level] = &n[level];
  }

  //set data node
  **c = n;
  return c;
}

/**
 * Insert a new element at the given cursor
 *
 * Sets & returns errno on failure, otherwise returns zero
 */
int ec_sl_insert(ec_sl_t *l, ec_sl_cursor_t *c, void *data) {
  if(!data)
    return EC_EUNDEFINED;
  //set element level
  int level = 1;
  while(level < EC_SL_MAXLEVEL && rand() % 2)
    level++;
  if(level > l->level)
    level = ++l->level;

  //allocate new element
  ec_sl_node_t *n = talloc_array(l, ec_sl_node_t, level + 1);
  if(!n)
    ec_err_r(ENOMEM, EC_ENOMEM, NULL);

  //insert element
  n->data = data;
  for(int i = level; i; i--) {
    n[i].next = (*c)[i]->next;
    (*c)[i]->next = n;
  }
  return 0;
}

/**
 * Get the element data for a given key. Returns NULL if not found.
 */
void *ec_sl_get(ec_sl_t *l, void *key) {
  if(!key)
    return NULL;
  ec_sl_node_t *n = l->start;
  for(int level = l->level; level; level--) {
    while(n[level].next && (!key || l->compfn(key, n[level].next->data) >= 0))
      n = n[level].next;
  }
  return (n->data && !l->compfn(key, n->data)) ? n->data : NULL;
}

/**
 * Set the element data for a given key. Creates the element if it doesn't exist.
 *
 * Sets & returns errno on failure, otherwise returns zero.
 */
int ec_sl_set(ec_sl_t *l, void *key, void *data, ec_sl_freefn_t freefn) {
  if(!key || !data)
    return EC_EUNDEFINED;
  ec_sl_cursor_t c;
  ec_sl_cursor(l, &c, key);
  if(c[1]->next && !l->compfn(key, c[1]->next->data)) {
    if(freefn && c[1]->next->data)
      freefn(c[1]->next->data);
    c[1]->next->data = data;
  }
  else
    return ec_sl_insert(l, &c, data);
  return 0;
}

/**
 * Remove the element for a given key, if it exists
 */
void ec_sl_remove(ec_sl_t *l, void *key, ec_sl_freefn_t freefn) {
  if(!key)
    return NULL;
  ec_sl_cursor_t c;
  ec_sl_cursor(l, &c, key);
  ec_sl_node_t *n = c[1]->next;
  if(n && !l->compfn(key, n->data)) {
    for(int level = l->level; level; level--) {
      if(c[level]->next == n)
        c[level]->next = n[level].next;
    }
    if(freefn && n[0].data)
      freefn(n[0].data);
    talloc_free(n);
  }
}
