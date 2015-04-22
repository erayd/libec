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

ec_err_t ec_role_has_section(ec_cert_t *c, char *role, char *section);

/**
 * Check whether a certificate has a role in the given section
 */
ec_err_t ec_role_has_section(ec_cert_t *c, char *role, char *section) {
  //identical match
  if(ec_match(c->records, section, 0, (unsigned char*)role, 0, NULL, 0))
    return EC_OK;

  //wildcard match
  char s[strlent(role) + 1];
  strcpy(s, role);
  char *pos = NULL;
  while(pos = strrchr(s, '.')) {
    strcpy(pos, ".*");
    if(ec_match(c->records, section, 0, (unsigned char*)s, 0, NULL, 0))
      return EC_OK;
    *pos = '\0';
  }

  //god-role match
  if(ec_match(c->records, section, 0, (unsigned char*)"*", 0, NULL, 0))
    return EC_OK;

  return EC_ENOTFOUND;
}

/**
 * Create a new role record
 */
ec_record_t *ec_role_add(ec_cert_t *c, char *role) {
  return ec_append(c, "_role", ec_record(EC_RECORD_KCOPY, (unsigned char*)role, 0, NULL, 0));
}

/**
 * Create a new grant record
 */
ec_record_t *ec_role_grant(ec_cert_t *c, char *grant) {
  return ec_append(c, "_grant", ec_record(EC_RECORD_KCOPY, (unsigned char*)grant, 0, NULL, 0));
}

/**
 * Check whether a certificate has the specified role
 */
ec_err_t ec_role_has(ec_cert_t *c, char *role) {
  return ec_role_has_section(c, role, "_role");
}

/**
 * Check whether a certificate grants the specified role
 */
ec_err_t ec_role_has_grant(ec_cert_t *c, char *role) {
  return ec_role_has_section(c, role, "_grant");
}
