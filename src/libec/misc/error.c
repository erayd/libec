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

/**
 * Get the string description for an error
 */
char *ec_errstr(ec_err_t error) {
  switch(error) {
    case EC_OK: return "OK";
    case EC_ENOTIMPLEMENTED: return "Not implemented";
    case EC_ENOMEM: return "Out of memory";
    case EC_ENOPK: return "No public key";
    case EC_ENOSK: return "No secret key";
    case EC_ESIGN: return "Bad signature";
    case EC_EFUTURE: return "Not yet valid";
    case EC_EEXPIRED: return "Expired";
    case EC_EVERSION: return "Invalid version";
    case EC_ENOSIGN: return "No signature";
    case EC_ESIZE: return "Incorrect size";
    case EC_ESIGNER: return "Signer not available";
    case EC_ESELF: return "Certificate is self-signed";
    case EC_ECHAIN: return "Bad trust chain";
    case EC_ERECORD: return "Invalid record";
    case EC_ENOTFOUND: return "No search results";
    case EC_EGRANT: return "Invalid grant";
    case EC_ETYPE: return "Invalid type";
    case EC_ESODIUM: return "Error in libsodium";
    case EC_EVALIDITY: return "Bad validity period";
    case EC_EINIT: return "Not initialised";
    case EC_EMAC: return "Bad MAC";
    case EC_ECHECK: return "Did not pass checks";
    case EC_ELOCKED: return "Certificate locked";
    case EC_ENOSALT: return "No salt";
    case EC_ENOCTX: return "No context";
    case EC_ENOVALIDATOR: return "No validator";
    case EC_EREQUIRED: return "Unable to validate required record";
    case EC_EUNKNOWN:
    default: return "Unknown error";
  }
}
