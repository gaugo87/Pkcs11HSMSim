#pragma once

#include "pkcs11.h"

namespace hsm
{

// AES-ECB encryption-based derivation with leading-byte truncation.
CK_RV DeriveKey(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism,
    CK_OBJECT_HANDLE baseKey, CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount,
    CK_OBJECT_HANDLE_PTR keyHandle);

} // namespace hsm
