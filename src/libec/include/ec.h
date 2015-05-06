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

#ifndef EC_EC_H
#define EC_EC_H

#include <stdint.h>
#include <time.h>

//libec error codes. For a string description, use ec_errstr().
typedef int ec_err_t;
char *ec_errstr(ec_err_t error);
#define EC_EOK 0
#define EC_OK EC_EOK
#define EC_EUNKNOWN 1 /*unknown error*/
#define EC_ENOTIMPLEMENTED 2 /*not implemented*/
#define EC_ENOMEM 3 /*out of memory*/
#define EC_ENOPK 4 /*no public key*/
#define EC_ENOSK 5 /*no secret key*/
#define EC_ESIGN 6 /*bad signature*/
#define EC_EFUTURE 7 /*not yet valid*/
#define EC_EEXPIRED 8 /*expired*/
#define EC_EVERSION 9 /*version*/
#define EC_ENOSIGN 10 /*no signature*/
#define EC_ESIZE 11 /*wrong size*/
#define EC_ESIGNER 12 /*signer not available*/
#define EC_ESELF 13 /*cert is self-signed*/
#define EC_ECHAIN 14 /*bad trust chain*/
#define EC_ERECORD 15 /*invalid record*/
#define EC_ENOTFOUND 16 /*no search results*/
#define EC_EGRANT 17 /*invalid grant*/
#define EC_ETYPE 18 /*invalid type*/

//flags
#define EC_CERT_TRUSTED (1 << 0) /*cert is a trust anchor*/

#define EC_RECORD_SECTION (1 << 0) /*record is a section header*/
#define EC_RECORD_REQUIRE (1 << 1) /*client *must* understand record / section*/
#define EC_RECORD_INHERIT (1 << 2) /*records will inherit flags from section header*/
#define EC_RECORD_NOSIGN (1 << 3) /*record will not be signed*/
#define EC_RECORD_KFREE (1 << 8) /*free record key when record is destroyed*/
#define EC_RECORD_KCOPY (1 << 9) /*copy record key*/
#define EC_RECORD_DFREE (1 << 10) /*free record data when record is destroyed*/
#define EC_RECORD_DCOPY (1 << 11) /*copy record data*/

#define EC_CHECK_CERT (1 << 0) /*basic structure checks*/
#define EC_CHECK_SIGN (1 << 1) /*certificate is signed*/
#define EC_CHECK_SECRET (1 << 2) /*secret key is present*/
#define EC_CHECK_CHAIN (1 << 3) /*check trust chain*/
#define EC_CHECK_ROLE (1 << 4) /*check roles & grants*/
#define EC_CHECK_ALL (~EC_CHECK_SECRET) /*all checks except SECRET*/

//limits
#define EC_EXPORT_OVERHEAD (sizeof(uint8_t) /*version*/ + sizeof(uint8_t) /*flags*/ \
  + sizeof(uint16_t) /*certificate length*/ + sizeof(uint8_t) /*NULL terminator*/)
#define EC_EXPORT_MIN EC_EXPORT_OVERHEAD
#define EC_EXPORT_MAX UINT16_MAX#define EC_RECORD_MAX (UINT16_MAX - EC_EXPORT_OVERHEAD) /*max length of packed record*/
#define EC_RECORD_MAX (UINT16_MAX - EC_EXPORT_OVERHEAD) /*max length of packed record*/
#define EC_RECORD_OVERHEAD (sizeof(uint16_t) /*record_len*/ + sizeof(uint8_t) /*key_len*/ + sizeof(uint8_t) /*flags*/)
#define EC_RECORD_MIN EC_RECORD_OVERHEAD
#define EC_RECORD_KMAX UINT8_MAX /*max length of record key*/
#define EC_RECORD_DMAX (EC_RECORD_MAX - EC_RECORD_KMAX - EC_RECORD_OVERHEAD) /*max length of record data*/

//various constants
#define EC_CERT_ID_BYTES 32

//basic types
typedef struct ec_ctx_t ec_ctx_t;
typedef struct ec_cert_t ec_cert_t;
typedef struct ec_record_t ec_record_t;



//create a new context
ec_ctx_t *ec_ctx_create(void);

//destroy a context
void ec_ctx_destroy(ec_ctx_t *ctx);

//set certificate autoloader
void ec_ctx_autoload(ec_ctx_t *ctx, ec_cert_t *(*autoload)(unsigned char *id));

//save certificate in context store
ec_cert_t *ec_ctx_save(ec_ctx_t *ctx, ec_cert_t *c);

//get certificate from context store
ec_cert_t *ec_ctx_cert(ec_ctx_t *ctx, unsigned char *id);



//create a new certificate
ec_cert_t *ec_cert_create(time_t valid_from, time_t valid_until);

//destroy a certificate
void ec_cert_destroy(ec_cert_t *c);

//hash a certificate
ec_err_t ec_cert_hash(unsigned char *hash, ec_cert_t *c);

//sign a certificate
ec_err_t ec_cert_sign(ec_cert_t *c, ec_cert_t *signer);

//check a certificate
ec_err_t ec_cert_check(ec_ctx_t *ctx, ec_cert_t *c, int flags);

//get the unique ID for a certificate
unsigned char *ec_cert_id(ec_cert_t *c);



//create a new record with binary key & data - use EC_RECORD_{KCOPY,KFREE,DCOPY,DFREE} for memory management
ec_record_t *ec_record_bin(uint16_t flags, unsigned char *key, uint8_t key_len, unsigned char *data, uint16_t data_len);

//create a new record with string key & data
ec_record_t *ec_record_str(uint16_t flags, char *key, char *data);

//create a new record with a string key & binary data
ec_record_t *ec_record(uint16_t flags, char *key, unsigned char *data, uint16_t data_len);

//append a record to a certificate
ec_record_t *ec_append(ec_cert_t *c, char *section, ec_record_t *r);

//find the first matching record in a record list using binary key & data
ec_record_t *ec_match_bin(ec_record_t *start, char *section, uint16_t flags, unsigned char *key, uint8_t key_len,
  unsigned char *data, uint16_t data_len);

//find the first matching record in a record list using string key & data
ec_record_t *ec_match_str(ec_record_t *start, char *section, uint16_t flags, char *key, char *data);

//find the first matching record in a record list using string key & binary data
ec_record_t *ec_match(ec_record_t *start, char *section, uint16_t flags, char *key, unsigned char *data,
  uint16_t data_len);

//set a string record
ec_record_t *ec_set(ec_cert_t *c, char *section, uint16_t flags, char *key, char *data);

//get the string data for a record with matching key / flags.
char *ec_get(ec_record_t *start, char *section, uint16_t flags, char *key);

//free a record, plus associated data if KFREE / DFREE is set
void ec_record_destroy(ec_record_t *r);



//add a role to a certificate
ec_record_t *ec_role_add(ec_cert_t *c, char *role);

//add a grant to a certificate
ec_record_t *ec_role_grant(ec_cert_t *c, char *role);

//check whether a certificate has the given role - returns nonzero error if it does not
ec_err_t ec_role_has(ec_cert_t *c, char *role);

//check whether a certificate grants the given role - returns nonzero error if it does not
ec_err_t ec_role_has_grant(ec_cert_t *c, char *role);


/* +++++++++++++++ EXPORTED DATA LAYOUT V2 +++++++++++++++
   
   Exported trust chain certificates are appended in order of ascending
   authority (e.g. cert, signer, signer's signer etc.)

   === Certificate Layout ===
    1B  (required) format version
    1B  (required) certificate flags
    2B  (required) certificate length
    4B  (required) valid_from
    4B  (required) valid_until
    32B (required) ed25519 public key
    32B (optional) ed25519 signer public key
    64B (optional) ed25519 signature (signed blake2b 512bit hash)
    64B (optional) ed25519 secret key
    <records>
    1B (required) NULL byte

   === Record Layout ===
    1B (required) record flags
    1B (required) record key length
    2B (required) record packed length
       (optional) record key
       (optional) record data

*/

//internal structures
struct ec_ctx_t {
  ec_ctx_t *next;
  ec_cert_t *(*autoload)(unsigned char *id);
  struct ec_sl_t *certs;
};

struct ec_cert_t {
  ec_record_t *records;
  unsigned char *pk;
  unsigned char *signer_id;
  unsigned char *signature;
  unsigned char *sk;
  uint32_t valid_from;
  uint32_t valid_until;
  uint8_t version;
  uint8_t flags;
};

struct ec_record_t {
  ec_record_t *next;
  unsigned char *key;
  unsigned char *data;
  uint16_t flags;
  uint16_t data_len;
  uint8_t key_len;
};

#endif