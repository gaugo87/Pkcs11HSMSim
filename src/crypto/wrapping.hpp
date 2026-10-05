#pragma once

#include "pkcs11.h"

namespace hsm
{

// AES wrapping and PKCS#8 serialization of private keys.
CK_RV WrapKey(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism,
    CK_OBJECT_HANDLE wrappingHandle, CK_OBJECT_HANDLE keyHandle, CK_BYTE_PTR output,
    CK_ULONG_PTR outputLength);
CK_RV UnwrapKey(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism,
    CK_OBJECT_HANDLE wrappingHandle, CK_BYTE_PTR input, CK_ULONG inputLength,
    CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_OBJECT_HANDLE_PTR keyHandle);

} // namespace hsm
