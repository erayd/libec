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
#define assert(condition, status, message) do {\
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
