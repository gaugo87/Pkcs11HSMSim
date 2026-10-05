#pragma once

#include "pkcs11.h"

namespace hsm
{

// Generation and persistence of symmetric keys and asymmetric key pairs.
CK_RV GenerateKey(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism,
    CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_OBJECT_HANDLE_PTR keyHandle);
CK_RV GenerateKeyPair(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism,
    CK_ATTRIBUTE_PTR publicTemplate, CK_ULONG publicCount, CK_ATTRIBUTE_PTR privateTemplate,
    CK_ULONG privateCount, CK_OBJECT_HANDLE_PTR publicHandle, CK_OBJECT_HANDLE_PTR privateHandle);
CK_RV GenerateRandom(CK_SESSION_HANDLE sessionHandle, CK_BYTE_PTR output, CK_ULONG length);

} // namespace hsm
