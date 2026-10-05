#pragma once

#include "pkcs11.h"

namespace hsm
{

// Signature operation lifecycle and EVP signing/verification.
CK_RV SignInit(
    CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE keyHandle);
CK_RV Sign(CK_SESSION_HANDLE sessionHandle, CK_BYTE_PTR data, CK_ULONG dataLength,
    CK_BYTE_PTR signature, CK_ULONG_PTR signatureLength);
CK_RV SignUpdate(CK_SESSION_HANDLE sessionHandle, CK_BYTE_PTR data, CK_ULONG dataLength);
CK_RV SignFinal(
    CK_SESSION_HANDLE sessionHandle, CK_BYTE_PTR signature, CK_ULONG_PTR signatureLength);
CK_RV VerifyInit(
    CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE keyHandle);
CK_RV Verify(CK_SESSION_HANDLE sessionHandle, CK_BYTE_PTR data, CK_ULONG dataLength,
    CK_BYTE_PTR signature, CK_ULONG signatureLength);
CK_RV VerifyUpdate(CK_SESSION_HANDLE sessionHandle, CK_BYTE_PTR data, CK_ULONG dataLength);
CK_RV VerifyFinal(CK_SESSION_HANDLE sessionHandle, CK_BYTE_PTR signature, CK_ULONG signatureLength);

} // namespace hsm
