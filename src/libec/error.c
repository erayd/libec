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

/**
 * Get the string description for an error
 */
char *ec_errstr(ec_err_t errno) {
  switch(errno) {
    case EC_OK: return "OK";
    case EC_ENOTIMPLEMENTED: return "Not implemented";
    case EC_EASSERT: return "Failed assertion";
    case EC_ENOMEM: return "Out of memory";
    case EC_EUNDEFINED: return "Attempted to use undefined variable";
    case EC_EMISSING: return "Missing data";
    case EC_ENOSECRET: return "No secret key";
    case EC_ETYPE: return "Invalid type";
    case EC_ESIZE: return "Invalid size";
    case EC_ECERT: return "Invalid certificate";
    case EC_ESIGNER: return "Imvalid signer";
    case EC_ESIGNATURE: return "Invalid signature";
    case EC_EEXPIRED: return "Certificate has expired";
    case EC_EFUTURE: return "Certificate is not yet valid";
    case EC_ESECTION: return "Missing section";
    case EC_ENOPUBLIC: return "No public key";
    case EC_ERECORD: return "Invalid record";
    case EC_EINTERNAL: return "Internal error";
    case EC_EMETHOD: return "Invalid signing method";
    case EC_ENOVALIDITY: return "Validity period not defined";
    case EC_ENOSIGNATURE: return "No signature";
    case EC_ENOCHAIN: return "Missing chain";
    case EC_ESELF: return "Illegal self-reference";
    case EC_ECHAIN: return "Invalid chain";
    case EC_ENOTFOUND: return "Search returned no results";
    case EC_EGRANT: return "Role not granted";
    case EC_EIMPORT: return "Import error";
    case EC_EUNKNOWN:
    default: return "Unknown error";
  }
}
