#include "crypto/derivation.hpp"
#include "crypto/key_generation.hpp"
#include "crypto/signature.hpp"
#include "crypto/wrapping.hpp"
#include "objects/attributes.hpp"
#include "objects/objects.hpp"
#include "pkcs11/boundary.hpp"
#include "pkcs11/sessions.hpp"
#include "pkcs11/token.hpp"

// Exported signatures remain exactly those declared by the OASIS headers.
CK_EXPORT CK_RV CK_CALL C_Initialize(CK_VOID_PTR pInitArgs)
{
    return hsm::invoke(false, hsm::Initialize, pInitArgs);
}

CK_EXPORT CK_RV CK_CALL C_Finalize(CK_VOID_PTR pReserved)
{
    return hsm::invoke(true, hsm::Finalize, pReserved);
}

CK_EXPORT CK_RV CK_CALL C_GetInfo(CK_INFO_PTR pInfo)
{
    return hsm::invoke(true, hsm::GetInfo, pInfo);
}

CK_EXPORT CK_RV CK_CALL C_GetSlotList(
    CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    return hsm::invoke(true, hsm::GetSlotList, tokenPresent, pSlotList, pulCount);
}

CK_EXPORT CK_RV CK_CALL C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    return hsm::invoke(true, hsm::GetSlotInfo, slotID, pInfo);
}

CK_EXPORT CK_RV CK_CALL C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    return hsm::invoke(true, hsm::GetTokenInfo, slotID, pInfo);
}

CK_EXPORT CK_RV CK_CALL C_GetMechanismList(
    CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    return hsm::invoke(true, hsm::GetMechanismList, slotID, pMechanismList, pulCount);
}

CK_EXPORT CK_RV CK_CALL C_GetMechanismInfo(
    CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    return hsm::invoke(true, hsm::GetMechanismInfo, slotID, type, pInfo);
}

CK_EXPORT CK_RV CK_CALL C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
    return hsm::invoke(true, hsm::OpenSession, slotID, flags, pApplication, Notify, phSession);
}

CK_EXPORT CK_RV CK_CALL C_CloseSession(CK_SESSION_HANDLE hSession)
{
    return hsm::invoke(true, hsm::CloseSession, hSession);
}

CK_EXPORT CK_RV CK_CALL C_CloseAllSessions(CK_SLOT_ID slotID)
{
    return hsm::invoke(true, hsm::CloseAllSessions, slotID);
}

CK_EXPORT CK_RV CK_CALL C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    return hsm::invoke(true, hsm::GetSessionInfo, hSession, pInfo);
}

CK_EXPORT CK_RV CK_CALL C_InitPIN(
    CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    return hsm::invoke(true, hsm::InitPIN, hSession, pPin, ulPinLen);
}

CK_EXPORT CK_RV CK_CALL C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
    CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    return hsm::invoke(true, hsm::SetPIN, hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
}

CK_EXPORT CK_RV CK_CALL C_Login(
    CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    return hsm::invoke(true, hsm::Login, hSession, userType, pPin, ulPinLen);
}

CK_EXPORT CK_RV CK_CALL C_Logout(CK_SESSION_HANDLE hSession)
{
    return hsm::invoke(true, hsm::Logout, hSession);
}

CK_EXPORT CK_RV CK_CALL C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    return hsm::invoke(true, hsm::DestroyObject, hSession, hObject);
}

CK_EXPORT CK_RV CK_CALL C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    return hsm::invoke(true, hsm::GetAttributeValue, hSession, hObject, pTemplate, ulCount);
}

CK_EXPORT CK_RV CK_CALL C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    return hsm::invoke(true, hsm::SetAttributeValue, hSession, hObject, pTemplate, ulCount);
}

CK_EXPORT CK_RV CK_CALL C_FindObjectsInit(
    CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    return hsm::invoke(true, hsm::FindObjectsInit, hSession, pTemplate, ulCount);
}

CK_EXPORT CK_RV CK_CALL C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    return hsm::invoke(
        true, hsm::FindObjects, hSession, phObject, ulMaxObjectCount, pulObjectCount);
}

CK_EXPORT CK_RV CK_CALL C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    return hsm::invoke(true, hsm::FindObjectsFinal, hSession);
}

CK_EXPORT CK_RV CK_CALL C_SignInit(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return hsm::invoke(true, hsm::SignInit, hSession, pMechanism, hKey);
}

CK_EXPORT CK_RV CK_CALL C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    return hsm::invoke(true, hsm::Sign, hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}

CK_EXPORT CK_RV CK_CALL C_SignUpdate(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return hsm::invoke(true, hsm::SignUpdate, hSession, pPart, ulPartLen);
}

CK_EXPORT CK_RV CK_CALL C_SignFinal(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    return hsm::invoke(true, hsm::SignFinal, hSession, pSignature, pulSignatureLen);
}

CK_EXPORT CK_RV CK_CALL C_VerifyInit(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return hsm::invoke(true, hsm::VerifyInit, hSession, pMechanism, hKey);
}

CK_EXPORT CK_RV CK_CALL C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    return hsm::invoke(true, hsm::Verify, hSession, pData, ulDataLen, pSignature, ulSignatureLen);
}

CK_EXPORT CK_RV CK_CALL C_VerifyUpdate(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return hsm::invoke(true, hsm::VerifyUpdate, hSession, pPart, ulPartLen);
}

CK_EXPORT CK_RV CK_CALL C_VerifyFinal(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    return hsm::invoke(true, hsm::VerifyFinal, hSession, pSignature, ulSignatureLen);
}

CK_EXPORT CK_RV CK_CALL C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
    return hsm::invoke(true, hsm::GenerateKey, hSession, pMechanism, pTemplate, ulCount, phKey);
}

CK_EXPORT CK_RV CK_CALL C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    return hsm::invoke(true, hsm::GenerateKeyPair, hSession, pMechanism, pPublicKeyTemplate,
        ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey,
        phPrivateKey);
}

CK_EXPORT CK_RV CK_CALL C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey,
    CK_ULONG_PTR pulWrappedKeyLen)
{
    return hsm::invoke(true, hsm::WrapKey, hSession, pMechanism, hWrappingKey, hKey, pWrappedKey,
        pulWrappedKeyLen);
}

CK_EXPORT CK_RV CK_CALL C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    return hsm::invoke(true, hsm::UnwrapKey, hSession, pMechanism, hUnwrappingKey, pWrappedKey,
        ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey);
}

CK_EXPORT CK_RV CK_CALL C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
    CK_OBJECT_HANDLE_PTR phKey)
{
    return hsm::invoke(
        true, hsm::DeriveKey, hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);
}

CK_EXPORT CK_RV CK_CALL C_GenerateRandom(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
    return hsm::invoke(true, hsm::GenerateRandom, hSession, RandomData, ulRandomLen);
}
