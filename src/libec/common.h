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

#include <config.h>
#include <ec.h>
#include <stdio.h>

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

//assert with debug output; used *ONLY* for cases that should never fail unless
//something is horribly wrong with the host system (e.g. out of memory, internal
//functions not returning to-spec results etc.)
#define ec_abort(condition, status, message) do {\
  if(!(condition)) {\
    fprintf(stderr, EC_CONSOLE_BOLD EC_CONSOLE_RED "EE [%s:%d]" EC_CONSOLE_RESET " %s\n", __FILE__, __LINE__,\
      message ?: "");\
    exit(status ?: EC_EASSERT);\
  }\
  if(DEBUG && DEBUG_PA) {\
    fprintf(stderr, EC_CONSOLE_GREEN "OK [%s:%d]" EC_CONSOLE_RESET " %s\n", __FILE__, __LINE__,\
      message ?: "");\
  }\
} while(0)

//if cond is nonzero, return cond
#define rfail(cond) do {for(ec_err_t status = (ec_err_t)(cond); status;) return status;} while(0);

//strlen including NULL terminator
#define strlent(s) (strlen((char*)s) + 1) /*strlen including NULL terminator*/

//given buffer is a NULL-terminated string
#define isstr(s, len) (len >= 1 && s[len - 1] == '\0') /*check whether a buffer of a given length is a valid string*/

//hash length for EC_METHOD_BLAKE2B_512
#define EC_METHOD_BLAKE2B_512_BYTES 64

//hash function for EC_METHOD_BLAKE2B_512
ec_err_t ec_method_blake2b_512_hash(unsigned char hash[EC_METHOD_BLAKE2B_512_BYTES], ec_cert_t *c);

//context type
struct ec_ctx_t {
  char *location;
  ec_err_t (*save)(ec_ctx_t ctx, ec_cert_t *c);
  ec_cert_t *(*load)(ec_ctx_t ctx, ec_id_t id);
  ec_err_t (*remove)(ec_ctx_t ctx, ec_id_t id);
  int flags;
};

//get the base64-armoured length for a buffer
size_t ec_base64_len(size_t length);

//encode a buffer into a base64 string
void ec_base64_encode(char *dest, unsigned char *src, size_t length);

//decode a base64 string into a buffer
void ec_base64_decode(unsigned char *dest, char *src, size_t length);

//put the contents of a buffer into a file
ec_err_t ec_file_put(char *path, unsigned char *buf, size_t length);

//get the contents of a file into a malloc()d buffer
ec_err_t ec_file_get(unsigned char **buf, size_t *length, char *path);
