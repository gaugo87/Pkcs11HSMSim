# Unreleased

- Ajout d'un test ML-DSA-44/65/87 : interopérabilité EVP, multipart,
  wrapping/unwrapping AES, PKCS#12 et rechargement du token.
- Script PowerShell VS2022/OpenSSL 3.5+ avec sélection de l'installation,
  configuration providers optionnelle, CTest et journal de diagnostic.
- Ces nouveaux parcours restent à valider dans l'environnement Windows cible.

# 0.6.0 — Official PKCS#11 3.2 headers and interface discovery

- User-provided OASIS pkcs11.h / pkcs11t.h / pkcs11f.h included byte-for-byte
  in include/oasis, preserving their original notices.
- Local include/pkcs11.h is now only a platform macro/packing adapter.
- All 104 official function signatures exported; unsupported operations have
  correctly typed CKR_FUNCTION_NOT_SUPPORTED implementations.
- Legacy C_GetFunctionList returns the 2.40 table.
- C_GetInterfaceList exposes PKCS 11 interfaces 3.2, 3.0 and 2.40.
- C_GetInterface supports name/version selection; default is 3.2.
- Tables are initialized using the official function list macros.
- GetInfo announces 3.2. This describes the API, not full feature conformance.
- Dynamic loader test: 385 checks, including all official 3.2 entries.
- Recompiled all existing tests with official headers: 464 regression/PSS/
  persistence checks plus RSA/AES smoke pass with OpenSSL 3.0.13 on Linux.
- Header parses as C and C++. Windows x64 layout assertions added but not run.
- PQC parameters/providers, session objects, certificate attributes, storage
  robustness and native VS2022/OpenSSL 3.5 verification remain pending.

# 0.5.0 — Typed exports and lifecycle boundary

- All 68 legacy entry points exported by name with typed prototypes.
- Removed generic no-argument function pointers from the function table.
- Function table is populated by field name to avoid positional mismatches.
- Header can be parsed as C or C++; Windows structures use packing 1.
- All operations except initialization/table discovery now check initialization
  before entering the implementation.
- Export boundary serializes access and translates C++ exceptions to CK_RV.
- Corrected advertised table/API version to 2.40; a historical table is not
  a full 3.2 interface. Existing PQC mechanism constants remain experimental.
- Dynamic loader test (154 checks) passes on Linux without linking the module.
- Prior RSA/AES smoke and 464 regression/PSS/persistence checks still pass.
- Official headers could not be downloaded; 3.2 discovery/tables remain blocked.
- Windows compiler/loader and independent OASIS-header ABI testing remain pending.

# 0.4.0 — Persistent labels and IDs

- Generation and unwrapping persist per-class labels and binary CKA_ID in
  versioned .meta sidecars. Public and private templates retain distinct labels.
- A CKA_ID supplied by only one key-pair template is shared by both objects;
  explicitly supplied IDs on both templates are retained separately.
- Exact labels are distinct from normalized filesystem names.
- Imported files without metadata use a stable SHA-256 filename-based default
  ID instead of implementation-dependent std::hash values (behavior change).
- Metadata format has field/file size limits, detects duplicates and corruption.
- Metadata publication uses a temporary file and rename. Failed publication
  rolls back newly created in-memory objects and attempts key-file removal.
- Search uses the same attribute implementation as GetAttributeValue.
- Deleting a file-backed object also removes its metadata sidecar.
- 84 persistence checks pass; prior 98 regression and 282 PSS checks plus
  the RSA/AES smoke test continue to pass.
- Key/metadata writes are not a cross-file crash-safe transaction; interprocess
  locking and independent deletion of the objects in a PKCS#12 remain pending.

# 0.3.0 — RSA-PSS

- Raw RSA-PSS and SHA-256/384/512 RSA-PSS signing and verification.
- Required PSS parameters are copied at initialization and checked for valid
  hash, MGF1 hash, salt length and consistency with the combined mechanism.
- Raw PSS validates digest length; combined mechanisms support multipart.
- PSS mechanisms appear in the mechanism list.
- Unknown signature mechanisms return CKR_MECHANISM_INVALID.
- Added 282 PSS checks, including independent EVP verification.
- Existing 98 regression checks and RSA/AES smoke test still pass.
- Windows/OpenSSL 3.5, PQC and complete PKCS#11 3.2 ABI remain unvalidated.

# 0.2.0 — Compatibility corrections (partial implementation)

- CKM_RSA_PKCS uses EVP_PKEY_sign/verify without hashing. The caller supplies
  the bytes to pad, including DigestInfo when appropriate.
- CKM_ECDSA signs a precomputed digest without hashing. All implemented ECDSA
  signatures use fixed-width r || s at the PKCS#11 boundary.
- EC key generation decodes the DER curve OID in CKA_EC_PARAMS.
- RSA modulus/exponent and EC parameters/point attributes are readable.
- Policy attributes are readable without enforcing their security policies.
- Private-key wrapping serializes PKCS#8; no wrapping of public-only objects.
- AES wrapping selects the cipher for the key length and computes exact
  wrapped output sizes. Default IV only; nonempty parameters are rejected.
- Generation/unwrapping refuses an existing destination filename. This is
  not yet an interprocess transactional storage layer.
- Hash-PQC mechanisms and nonempty signature parameters are explicitly rejected
  instead of silently running a different operation.
- Multipart buffering is capped at 64 MiB. Raw RSA/ECDSA mechanisms reject Update.
- Tests retain their checks in Release builds and use isolated token directories.
- 98 regression checks pass with GCC 13 / OpenSSL 3.0.13, including independent
  OpenSSL verification of raw RSA, raw ECDSA and ECDSA-SHA256.

## Still required before the original specification is fulfilled

- Official OASIS headers, independent Windows packing validation,
  a full 3.2 table and C_GetInterface / C_GetInterfaceList. The current custom
  legacy table must not be considered a complete 3.2 ABI.
- Windows VS2022/OpenSSL 3.5 compilation and dynamic-loader testing.
- PQC runtime testing, contexts, hedging and hash variants.
- Optional OAEP (RSA-PSS implemented in 0.3).
- Session objects, certificate metadata and per-object deletion semantics.
- Atomic storage, interprocess locking, strict import validation and diagnostics.
- Complete argument/error/state handling and interprocess concurrency.
- External PKCS#11 client interoperability tests.
