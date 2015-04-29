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
    case EC_EINVALID: return "Invalid data";
    case EC_EFILE: return "File error";
    case EC_EEMPTY: return "Empty";
    case EC_ENOCID: return "No certificate ID";
    case EC_EUNKNOWN:
    default: return "Unknown error";
  }
}
