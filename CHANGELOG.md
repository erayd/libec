#Changelog

##[Unreleased](https://github.com/erayd/libec/tree/dev)

###New Interfaces
 * ec_ctx_remove()
 * ec_ctx_anchor()

###Enhancements
 * Add interface to remove certificate from context store
 * Add interface to get the trust anchor for a certificate

##[v0.2.0-dev](https://github.com/erayd/libec/releases/tag/v0.2.0-dev)

###New Interfaces
 * ec_cert_copy()
 * ec_cert_strip()
 * ec_ctx_validator()


###Changed Interfaces
 * ec_import()
 * ec_import_64()

###Enhancements
 * Add interface for copying certificates
 * Require ending block for base64 import
 * Track number of bytes consumed on import
 * Add validation for required records
 * Improve use of talloc destructors
 * Add interface for stripping unwanted data from certificates
 * Require any section beginning with '$' to be signed

###Bugfixes
 * Lock sensitive key material in memory
 * Records added to a NOSIGN section must also have NOSIGN set
 * First record in a certificate must be a section header
 * Roles & grants must be signed
 * Pointer arithmetic bug in base64 decode when encountering an invalid char
 * Remove potential for NULL pointer dereference in skiplists


##[v0.2.0-dev](https://github.com/erayd/libec/releases/tag/v0.2.0-dev)

Initial development release.
