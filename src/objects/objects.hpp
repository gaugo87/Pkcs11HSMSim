#pragma once

#include "pkcs11.h"

namespace hsm
{

// Object search and deletion, including shared-file key-pair ownership.
CK_RV DestroyObject(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE objectHandle);
CK_RV FindObjectsInit(
    CK_SESSION_HANDLE sessionHandle, CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount);
CK_RV FindObjects(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE_PTR objects, CK_ULONG capacity,
    CK_ULONG_PTR count);
CK_RV FindObjectsFinal(CK_SESSION_HANDLE sessionHandle);

} // namespace hsm
