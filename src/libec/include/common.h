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

#ifndef EC_COMMON_H
#define EC_COMMON_H

#include <config.h>
#include <include/ec.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <error.h>

//not using debug mode
#ifndef DEBUG
#define DEBUG 0
#endif

//not caring about successful assertions
#ifndef DEBUG_PA
#define DEBUG_PA 0
#endif

//terminal output formatting
#define EC_CONSOLE_RESET "\033[0m"
#define EC_CONSOLE_BOLD "\033[1m"
#define EC_CONSOLE_RED "\033[31m"
#define EC_CONSOLE_GREEN "\033[32m"

//print error
#define ec_err(error, ...) do {\
  if(error)\
    errno = error;\
  error_at_line(EXIT_SUCCESS, errno, __FILE__, __LINE__, __VA_ARGS__);\
} while(0)

//print error and return
#define ec_err_r(error, retval, ...) do {\
  ec_err(error, __VA_ARGS__);\
  return retval;\
} while(0)

//assert with debug output; used *ONLY* for cases that should never fail unless
//something is horribly wrong with the host system (e.g. out of memory, internal
//functions not returning to-spec results etc.)
#define ec_abort(condition, status, message) do {\
  if(!(condition)) {\
    fprintf(stderr, EC_CONSOLE_BOLD EC_CONSOLE_RED "EE [%s:%d]" EC_CONSOLE_RESET " %s\n", __FILE__, __LINE__,\
      message ?: "");\
    exit(status ?: EC_EUNKNOWN);\
  }\
  if(DEBUG && DEBUG_PA) {\
    fprintf(stderr, EC_CONSOLE_GREEN "OK [%s:%d]" EC_CONSOLE_RESET " %s\n", __FILE__, __LINE__,\
      message ?: "");\
  }\
} while(0)

//if cond is nonzero, return cond
#define rfail(cond) do {for(ec_err_t __status = (ec_err_t)(cond); __status;) return __status;} while(0);

//strlen including NULL terminator
#define strlent(s) (strlen((char*)s) + 1) /*strlen including NULL terminator*/

//given buffer is a NULL-terminated string
#define isstr(s, len) (len >= 1 && s[len - 1] == '\0') /*check whether a buffer of a given
                                                         length is a valid string*/
//hash length for EC_METHOD_BLAKE2B_512
#define EC_METHOD_BLAKE2B_512_BYTES 64

//layout version
#define EC_LAYOUT_VERSION 2

//free pointers on failure - last arg must be NULL
int fmalloc_canary;
#define fmalloc(size, ...) fmalloc_real(size, &fmalloc_canary, __VA_ARGS__, &fmalloc_canary)
#define fcalloc(size, ...) fmalloc_real(size, &fmalloc_canary, __VA_ARGS__, &fmalloc_canary)
void *fmalloc_real(size_t size, void *canary, ...);
void *fcalloc_real(size_t size, void *canary, ...);

//skiplist
#define EC_SL_MAXLEVEL (sizeof(unsigned) * CHAR_BIT)
#define EC_SL_CURSOR_SLOTS (EC_SL_MAXLEVEL + 1)

typedef int (*ec_sl_compfn_t)(void *key, void *ptr);
typedef void (*ec_sl_freefn_t)(void *data);

typedef union ec_sl_node_t {
  union ec_sl_node_t *next;
  void *data;
} ec_sl_node_t;

typedef ec_sl_node_t *ec_sl_cursor_t[EC_SL_CURSOR_SLOTS];

typedef struct ec_sl_t {
  ec_sl_compfn_t compfn;
  ec_sl_node_t start[EC_SL_CURSOR_SLOTS];
  unsigned level;
} ec_sl_t;

ec_sl_t *ec_sl_create(ec_sl_compfn_t compfn);
void ec_sl_destroy(ec_sl_t *l, ec_sl_freefn_t freefn);
ec_sl_cursor_t *ec_sl_cursor(ec_sl_t *l, ec_sl_cursor_t *c, void *key);
int ec_sl_insert(ec_sl_t *l, ec_sl_cursor_t *c, void *data);
void *ec_sl_get(ec_sl_t *l, void *key);
int ec_sl_set(ec_sl_t *l, void *key, void *data, ec_sl_freefn_t freefn);
void ec_sl_remove(ec_sl_t *l, void *key, ec_sl_freefn_t freefn);

//base64
#define EC_EXPORT_BEGIN "--------------------- BEGIN EXPORTED EC CERTIFICATE --------------------"
#define EC_EXPORT_END "---------------------- END EXPORTED EC CERTIFICATE ---------------------"
size_t ec_base64_len(size_t length);
size_t ec_base64_encode(char *dest, unsigned char *src, size_t length);
size_t ec_base64_decode(unsigned char *dest, char *src, size_t length);
#endif
