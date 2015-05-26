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
#include <sodium.h>

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
#define EC_ESODIUM 19 /*libsodium error*/
#define EC_EVALIDITY 20 /*bad validity period*/
#define EC_EINIT 21 /*not initialised*/
#define EC_EMAC 22 /*failed mac*/
#define EC_ECHECK 23 /*faild checks*/
#define EC_ELOCKED 24 /*certificate is locked*/
#define EC_ENOSALT 25 /*no salt*/
#define EC_ENOCTX 26 /*no context*/
#define EC_ENOVALIDATOR 27 /*no validator*/
#define EC_EREQUIRED 28 /*required record does not validate*/
#define EC_EUNDEFINED 29 /*undefined data*/

//flags
#define EC_CERT_TRUSTED (1 << 0) /*cert is a trust anchor*/
#define EC_CERT_CRYPTSK (1 << 1) /*secret is encrypted*/

#define EC_RECORD_SECTION (1 << 0) /*record is a section header*/
#define EC_RECORD_REQUIRE (1 << 1) /*client *must* understand record / section*/
#define EC_RECORD_INHERIT (1 << 2) /*records will inherit flags from section header*/
#define EC_RECORD_NOSIGN (1 << 3) /*record will not be signed*/
#define EC_RECORD_KFREE (1 << 8) /*free record key when record is destroyed*/
#define EC_RECORD_KCOPY (1 << 9) /*copy record key*/
#define EC_RECORD_DFREE (1 << 10) /*free record data when record is destroyed*/
#define EC_RECORD_DCOPY (1 << 11) /*copy record data*/
#define EC_RECORD_KALLOC (1 << 12) /*allocate empty buffer for key*/
#define EC_RECORD_DALLOC (1 << 13) /*allocate empty buffer for data*/

#define EC_MATCH_FLAGS (1 << 0) /*flags must match*/
#define EC_MATCH_KEY (1 << 1) /*key must match*/
#define EC_MATCH_KEY_LEN (1 << 2) /*key length must match*/
#define EC_MATCH_DATA (1 << 3) /*data must match*/
#define EC_MATCH_DATA_LEN (1 << 4) /*data length must match*/

#define EC_CHECK_CERT (1 << 0) /*basic structure checks*/
#define EC_CHECK_SIGN (1 << 1) /*certificate is signed*/
#define EC_CHECK_SECRET (1 << 2) /*secret key is present*/
#define EC_CHECK_CHAIN (1 << 3) /*check trust chain*/
#define EC_CHECK_ROLE (1 << 4) /*check roles & grants*/
#define EC_CHECK_REQUIRE (1 << 5) /*check required records*/
#define EC_CHECK_ALL (~EC_CHECK_SECRET) /*all checks except SECRET*/

#define EC_STRIP_SECRET (1 << 0) /*strip secret key*/
#define EC_STRIP_RECORD (1 << 1) /*strip NOSIGN records*/
#define EC_STRIP_SIGN (1 << 2) /*strip signer_id & signature*/

#define EC_EXPORT_SECRET (1 << 0) /*include secret key in exported cert*/
#define EC_EXPORT_SIGNER (1 << 1) /*include signer_id in exported cert*/
#define EC_EXPORT_SIGNATURE (1 << 2) /*include signature in exported cert*/

//limits
#define EC_EXPORT_HEADER (sizeof(uint8_t) * 3 /*version, flags & export flags*/ \
  + sizeof(uint16_t) /*cert length*/ + sizeof(uint32_t) * 2 /* validity period */ \
  + 32 * 2 /*pk & signer id*/ + 64 * 2 /*sk & signature*/)
#define EC_EXPORT_OVERHEAD (EC_EXPORT_HEADER + 1 /* NULL terminator*/)
#define EC_EXPORT_MIN (sizeof(uint32_t) * 3 /*version, flags & export flags*/ \
  + sizeof(uint16_t) /*cert length*/ + sizeof(uint32_t) * 2 /* validity period */ \
  + 32 /*pk*/ + 1 /*NULL terminator*/)
#define EC_EXPORT_MAX UINT16_MAX
#define EC_RECORD_MAX (UINT16_MAX - EC_EXPORT_OVERHEAD) /*max length of packed record*/
#define EC_RECORD_OVERHEAD (sizeof(uint16_t) /*record_len*/ + sizeof(uint8_t) /*key_len*/ + sizeof(uint8_t) /*flags*/)
#define EC_RECORD_MIN EC_RECORD_OVERHEAD
#define EC_RECORD_KMAX UINT8_MAX /*max length of record key*/
#define EC_RECORD_DMAX (EC_RECORD_MAX - EC_RECORD_KMAX - EC_RECORD_OVERHEAD) /*max length of record data*/

//various constants
#define EC_CERT_ID_BYTES 32
#define EC_CHANNEL_MAC_BYTES crypto_box_MACBYTES
#define EC_CHANNEL_DH_BYTES (EC_CERT_ID_BYTES + crypto_box_PUBLICKEYBYTES \
  + crypto_box_NONCEBYTES + crypto_sign_BYTES)

//basic types
typedef struct ec_ctx_t ec_ctx_t;
typedef struct ec_cert_t ec_cert_t;
typedef struct ec_record_t ec_record_t;
typedef struct ec_channel_t ec_channel_t;
typedef unsigned char *ec_id_t;
typedef ec_cert_t *(*ec_autoload_t)(ec_id_t id);
typedef int (*ec_record_validator_t)(ec_ctx_t *ctx, ec_cert_t *c, ec_record_t *r);



//nitialise library - must be called before any other function
ec_err_t ec_init(void);

//return library version
char *ec_version(void);



//create a new context
ec_ctx_t *ec_ctx_create(void);

//destroy a context
void ec_ctx_destroy(ec_ctx_t *ctx);

//set certificate autoloader
void ec_ctx_autoload(ec_ctx_t *ctx, ec_autoload_t autoload);

//set record validator
void ec_ctx_validator(ec_ctx_t *ctx, ec_record_validator_t validator);

//sets the next context to search
ec_ctx_t *ec_ctx_next(ec_ctx_t *ctx, ec_ctx_t *next);

//save certificate in context store
ec_cert_t *ec_ctx_save(ec_ctx_t *ctx, ec_cert_t *c);

//remove certificate from context store
ec_cert_t *ec_ctx_remove(ec_ctx_t *ctx, ec_id_t id);

//get certificate from context store
ec_cert_t *ec_ctx_cert(ec_ctx_t *ctx, ec_id_t id);

//get the trust anchor for a certificate
ec_cert_t *ec_ctx_anchor(ec_ctx_t *ctx, ec_cert_t *c);



//create a new certificate
ec_cert_t *ec_cert_create(time_t valid_from, time_t valid_until);

//copy a certificate
ec_cert_t *ec_cert_copy(ec_cert_t *c);

//destroy a certificate
void ec_cert_destroy(ec_cert_t *c);

//strip data from a certificate
void ec_cert_strip(ec_cert_t *c, int what);

//sign a certificate
ec_err_t ec_cert_sign(ec_cert_t *c, ec_cert_t *signer);

//check a certificate
ec_err_t ec_cert_check(ec_ctx_t *ctx, ec_cert_t *c, int flags);

//get the unique ID for a certificate
ec_id_t ec_cert_id(ec_cert_t *c);

//get the record list for a certificate
ec_record_t *ec_cert_records(ec_cert_t *c);

//encrypt a secret key
ec_err_t ec_cert_lock(ec_cert_t *c, char *password);

//decrypt a secret key
ec_err_t ec_cert_unlock(ec_cert_t *c, char *password);



//create a new record with binary key & data - use EC_RECORD_{KCOPY,KFREE,DCOPY,DFREE} for memory management
ec_record_t *ec_record_bin(uint16_t flags, unsigned char *key, uint8_t key_len, unsigned char *data,
  uint16_t data_len);

//create a new record with string key & data
ec_record_t *ec_record_str(uint16_t flags, char *key, char *data);

//create a new record with a string key & binary data
ec_record_t *ec_record_create(uint16_t flags, char *key, unsigned char *data, uint16_t data_len);

//append a record to a certificate
ec_record_t *ec_record_add(ec_cert_t *c, char *section, ec_record_t *r);

//remove a record from a certificate
ec_record_t *ec_record_remove(ec_cert_t *c, ec_record_t *r);

//find the first matching record in a record list using binary key & data
ec_record_t *ec_record_match_bin(ec_record_t *start, char *section, uint16_t flags, unsigned char *key,
  uint8_t key_len, unsigned char *data, uint16_t data_len);

//find the first matching record in a record list using string key & data
ec_record_t *ec_record_match_str(ec_record_t *start, char *section, uint16_t flags, char *key, char *data);

//find the first matching record in a record list using string key & binary data
ec_record_t *ec_record_match(ec_record_t *start, char *section, uint16_t flags, char *key,
  unsigned char *data, uint16_t data_len);

//get the next matching record in the same section
ec_record_t *ec_record_next(ec_record_t *start, int filter);

//set a string record
ec_record_t *ec_record_set(ec_cert_t *c, char *section, uint16_t flags, char *key, char *data);

//get the string data for a record with matching key / flags.
char *ec_record_get(ec_record_t *start, char *section, uint16_t flags, char *key);

//get the section for a record
char *ec_record_section(ec_record_t *r);

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



//get the required buffer length to export a certificate
uint16_t ec_export_len(ec_cert_t *c, uint8_t export_flags);

//export a certificate
size_t ec_export(unsigned char *dest, ec_cert_t *c, uint8_t export_flags);

//import a certificate
ec_cert_t *ec_import(unsigned char *src, size_t length, size_t *consumed);

//get the required buffer length to export a certificate to base64
size_t ec_export_len_64(ec_cert_t *c, uint8_t export_flags);

//export a certificate to base64
char *ec_export_64(char *dest, ec_cert_t *c, uint8_t export_flags);

//import a cert from base64
ec_cert_t *ec_import_64(char *src, size_t length, size_t *consumed);


//zero channel state
void ec_channel_clean(ec_channel_t *ch);

//initialise a channel
ec_err_t ec_channel_init(ec_channel_t *ch, ec_cert_t *c, ec_ctx_t *ctx, unsigned char *dh);

//make a channel ready for use (second half of D/H)
ec_err_t ec_channel_start(ec_channel_t *ch, unsigned char *dh, int checks);

//encrypt a buffer
ec_err_t ec_channel_encrypt(ec_channel_t *ch, unsigned char *buf, size_t len,
  unsigned char *mac, uint64_t *ctr);

//decrypt a buffer
ec_err_t ec_channel_decrypt(ec_channel_t *ch, unsigned char *buf, size_t len,
  unsigned char *mac, uint64_t ctr);

//get the remote cert
ec_cert_t *ec_channel_remote(ec_channel_t *ch);

/* +++++++++++++++ EXPORTED DATA LAYOUT V2 +++++++++++++++
   
   Exported trust chain certificates are appended in order of ascending
   authority (e.g. cert, signer, signer's signer etc.)

   === Certificate Layout ===
    1B  (required) layout version
    2B  (required) certificate length
    1B  (required) certificate flags
    1B  (required) export flags
    4B  (required) valid_from
    4B  (required) valid_until
    32B (required) ed25519 public key
    32B (optional) ed25519 signer id
    64B (optional) ed25519 signature (signed blake2b 512bit hash)
    64B (optional) ed25519 secret key
    32B (optional) salt for password-encryption of secret key
    <records>
    1B (required) NULL byte

   === Record Layout ===
    2B (required) record packed length
    1B (required) record flags
    1B (required) record key length
       (optional) record key
       (optional) record data

*/

//internal structures
struct ec_ctx_t {
  ec_ctx_t *next;
  ec_autoload_t autoload;
  ec_record_validator_t validator;
  struct ec_sl_t *certs;
};

struct ec_cert_t {
  ec_record_t *records;
  ec_id_t signer_id;
  unsigned char *pk;
  unsigned char *signature;
  unsigned char *sk;
  unsigned char *salt;
  uint32_t valid_from;
  uint32_t valid_until;
  uint8_t version;
  uint8_t flags;
};

struct ec_record_t {
  ec_record_t *next;
  ec_record_t *section;
  unsigned char *key;
  unsigned char *data;
  uint16_t flags;
  uint16_t data_len;
  uint8_t key_len;
};

struct ec_channel_t {
  ec_ctx_t *ctx;
  ec_cert_t *c;
  ec_cert_t *remote;
  unsigned char pk[crypto_box_PUBLICKEYBYTES];
  unsigned char sk[crypto_box_SECRETKEYBYTES];
  unsigned char key[crypto_box_BEFORENMBYTES];
  unsigned char nonce_local[crypto_box_NONCEBYTES];
  unsigned char nonce_remote[crypto_box_NONCEBYTES];
  uint64_t ctr;
  enum {
    START,
    READY
  } state;
};

#endif
