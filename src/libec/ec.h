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

#include <stdlib.h>
#include <stdint.h>

//libec error codes. For a string description, use ec_errstr().
typedef int ec_err_t;
char *ec_errstr(ec_err_t errno);
#define EC_EOK 0
#define EC_OK EC_EOK
#define EC_ENOTIMPLEMENTED 1 /*not implemented*/
#define EC_EUNKNOWN 2 /*unknown error*/
#define EC_EASSERT 3 /*failed assertion*/
#define EC_ENOMEM 4 /*out of memory*/
#define EC_EUNDEFINED 5 /*attempt to use undefined variable*/
#define EC_EMISSING 6 /*missing data*/
#define EC_ENOSECRET 7 /*mising secret key*/
#define EC_ETYPE 8 /*invalid type*/
#define EC_ESIZE 9 /*invalid size*/
#define EC_ECERT 10 /*invalid certificate*/
#define EC_ESIGNER 11 /*invalid signer*/
#define EC_ESIGNATURE 12 /*invalid signature*/
#define EC_EEXPIRED 13 /*certificate has expired*/
#define EC_EFUTURE 14 /*certificate is not yet valid*/
#define EC_ESECTION 15 /*missing section*/
#define EC_ENOPUBLIC 16 /*missing public key*/
#define EC_ERECORD 17 /*invalid record*/
#define EC_EINTERNAL 18 /*unknown internal error*/
#define EC_EMETHOD 19 /*invalid signing method*/
#define EC_ENOVALIDITY 20 /*validity period not defined*/
#define EC_ENOSIGNATURE 21 /*missing signature*/
#define EC_ENOCHAIN 22 /*missing chain*/
#define EC_ESELF 23 /*illegal self-reference*/
#define EC_ECHAIN 24 /*invalid chain*/
#define EC_ENOTFOUND 25 /*search returned no results*/
#define EC_EGRANT 26 /*role not granted*/
#define EC_EIMPORT 27 /*import error*/

//certificate flags
#define EC_CERT_TRUSTED (1 << 8) /*<not exported> certificate is considered a trusted root*/

//record flags
#define EC_RECORD_SECTION (1 << 0) /*record is a section start*/
#define EC_RECORD_INHERIT (1 << 1) /*record will inherit flags from section*/
#define EC_RECORD_NOSIGN (1 << 2) /*record will not be signed*/
#define EC_RECORD_KCOPY (1 << 8) /*<not exported> copy key when creating record - implies KFREE*/
#define EC_RECORD_KFREE (1 << 9) /*<not exported> free key when destroying record*/
#define EC_RECORD_DCOPY (1 << 10) /*<not exported> copy data when creating record - implies DFREE*/
#define EC_RECORD_DFREE (1 << 11) /*<not exported> free data when destroying record*/

//available tests for ec_check()
#define EC_CHECK_CERT (1 << 0) /*check basic certificate structure - is enabled by default*/
#define EC_CHECK_SECRET (1 << 1) /*check that the certificate has a valid secret*/
#define EC_CHECK_SIGNED (1 << 2) /*check that the certificate has a valid signature*/
#define EC_CHECK_CHAIN (1 << 3) /*check that the certificate has a valid trust chain (implies SIGNED)*/
#define EC_CHECK_ROLE (1 << 4) /*check that the certificate's roles and grants are valid (implies CHAIN)*/
#define EC_CHECK_ALL (0xFF) /*perform all checks*/

//import & export options
#define EC_EXPORT_CHAIN (1 << 0) /*also export certificate's attached trust chain*/
#define EC_EXPORT_TRUSTED (1 << 1) /*also export chain's trust anchor (implies CHAIN)*/
#define EC_EXPORT_ROOT EC_EXPORT_TRUSTED /*alias of EC_EXPORT_TRUSTED*/
#define EC_EXPORT_SECRET (1 << 2) /*also export certificate's secret key*/
#define EC_IMPORT_CHAIN (1 << 0) /*also import trust chain, if attached*/

//various internal settings
#define EC_CERT_VERSION 1 /*format version for new certificates*/
#define EC_DEFAULT_VALIDITY (365 * 86400) /*default signature validity (one year)*/

//various certificate constants
#define EC_TYPE_ED25519 "ed25519"
#define EC_METHOD_BLAKE2B_512 "blake2b_512"

//internal limits
#define EC_EXPORT_OVERHEAD (sizeof(uint8_t) /*version*/ + sizeof(uint8_t) /*flags*/ \
  + sizeof(uint16_t) /*certificate length*/ + sizeof(uint8_t) /*NULL terminator*/)
#define EC_EXPORT_MIN EC_EXPORT_OVERHEAD
#define EC_EXPORT_MAX UINT16_MAX
#define EC_RECORD_MAX (UINT16_MAX - EC_EXPORT_OVERHEAD) /*max length of packed record*/
#define EC_RECORD_OVERHEAD (sizeof(uint16_t) /*record_len*/ + sizeof(uint8_t) /*key_len*/ + sizeof(uint8_t) /*flags*/)
#define EC_RECORD_MIN EC_RECORD_OVERHEAD
#define EC_RECORD_KMAX UINT8_MAX /*max length of record key*/
#define EC_RECORD_DMAX (EC_RECORD_MAX - EC_RECORD_KMAX - EC_RECORD_OVERHEAD) /*max length of record data*/

//base64 export envelope
#define EC_EXPORT_BEGIN "---------------- BEGIN EXPORTED EC CERTIFICATE ----------------"
#define EC_EXPORT_END "---------------- END EXPORTED EC CERTIFICATE ----------------"

//certificate type
typedef struct ec_cert_t {
  struct ec_cert_t *signer;
  struct ec_record_t *records;
  uint16_t flags;
  uint8_t version;
} ec_cert_t;

//record type
typedef struct ec_record_t {
  struct ec_record_t *next;
  unsigned char *key;
  unsigned char *data;
  uint16_t flags;
  uint16_t data_len;
  uint8_t key_len;
} ec_record_t;

//create a new record - use EC_RECORD_{KCOPY,KFREE,DCOPY,DFREE} for memory management
ec_record_t *ec_record(uint16_t flags, unsigned char *key, uint8_t key_len, unsigned char *data, uint16_t data_len);

//append a record to a certificate
ec_record_t *ec_append(ec_cert_t *c, char *section, ec_record_t *r);

//find the first matching record in a record list
ec_record_t *ec_match(ec_record_t *start, char *section, uint16_t flags, unsigned char *key, uint8_t key_len,
  unsigned char *data, uint16_t data_len);

//free a record, plus associated data if KFREE / DFREE is set
void ec_record_destroy(ec_record_t *r);

//create a new certificate
ec_cert_t *ec_cert(void);

//sign a certificate and set the validity period
ec_err_t ec_sign(ec_cert_t *c, ec_cert_t *signer, uint64_t valid_from, uint64_t valid_until);

//check that a certificate is valid. See EC_CHECK_* for possible tests.
ec_err_t ec_check(ec_cert_t *c, int checks);

//compare two certificates - returns zero if equal, arbitrary nonzero otherwise
int ec_certcmp(ec_cert_t *c1, ec_cert_t *c2);

//free a certificate and all attached records
void ec_cert_destroy(ec_cert_t *c);

//add a role to a certificate
ec_record_t *ec_role_add(ec_cert_t *c, char *role);

//add a grant to a certificate
ec_record_t *ec_role_grant(ec_cert_t *c, char *role);

//check whether a certificate has the given role - returns nonzero error if it does not
ec_err_t ec_role_has(ec_cert_t *c, char *role);

//check whether a certificate grants the given role - returns nonzero error if it does not
ec_err_t ec_role_has_grant(ec_cert_t *c, char *role);

//get the export length for a certificate
size_t ec_export_len(ec_cert_t *c, int flags);

//export a certificate
ec_err_t ec_export(unsigned char *dest, ec_cert_t *c, int flags);

//import a certificate
ec_cert_t *ec_import(unsigned char *src, size_t src_len, int flags);

/* +++++++++++++++ EXPORTED DATA LAYOUT V1 +++++++++++++++
   
   Exported trust chain certificates are appended in order of ascending
   authority (e.g. cert, signer, signer's signer etc.)

   === Certificate Layout ===
    1B (required) format version
    1B (required) certificate flags
    2B (required) certificate length
    <records>
    1B (required) NULL byte

   === Record Layout ===
    2B (required) record packed length
    1B (required) record key length
    1B (required) record flags
       (optional) record key
       (optional) record data

*/
