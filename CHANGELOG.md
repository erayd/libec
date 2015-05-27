#Changelog

##[Unreleased](https://github.com/erayd/libec/tree/dev)

###New Interfaces
 * ec_ctx_remove()
 * ec_ctx_anchor()
 * ec_record_next()
 * ec_record_remove()
 * ec_record_remove_section()
 * ec_record_data()
 * ec_record_buf()

###Changed Interfaces
 * Rename ec_record() -> ec_record_create()
 * Rename ec_match() -> ec_record_match()
 * Rename ec_match_bin() -> ec_record_match_bin()
 * Rename ec_match_str() -> ec_record_match_str()
 * Rename ec_add() -> ec_record_add()
 * Rename ec_set() -> ec_record_set()
 * Rename ec_get() -> ec_record_get()

###Enhancements
 * Add interface to remove certificate from context store
 * Add interface to get the trust anchor for a certificate
 * Add interface to get the next matching record in a section
 * Add interfaces to remove records from a certificate
 * Add interface to get a pointer to the data buffer for a record
 * Refactor to properly comply with C99 (removes GNU extensions)
 * Add pkg-config info
 * Add flags to allocate an empty buffer when creating a record
 * Allow searches to exclude NOSIGN records
 * Add interface to quickly get or create a record buffer of minimum length

###Bugfixes
 * Don't try to validate a NULL pointer when checking certificates
 * Fix memory leak in context test suite
 * Don't try to destroy NULL pointers in ec_record_destroy()

##[v0.2.1-dev](https://github.com/erayd/libec/releases/tag/v0.2.1-dev)

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
