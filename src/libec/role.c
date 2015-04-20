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
