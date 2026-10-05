#include "pkcs11/boundary.hpp"

// Unsupported operations still validate initialization through the common boundary.
CK_EXPORT CK_RV CK_CALL C_InitToken(
    CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_InitPIN(
    CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
    CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_GetOperationState(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
    CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey,
    CK_OBJECT_HANDLE hAuthenticationKey)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_GetObjectSize(
    CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_EncryptInit(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
    CK_ULONG_PTR pulLastEncryptedPartLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_DecryptInit(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_DecryptFinal(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_DigestUpdate(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_DigestFinal(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_SignRecoverInit(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_VerifyRecoverInit(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_SeedRandom(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_CancelFunction(CK_SESSION_HANDLE hSession)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_WaitForSlotEvent(
    CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pRserved)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_LoginUser(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
    CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_MessageEncryptInit(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_EncryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
    CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen,
    CK_BYTE_PTR pPlaintext, CK_ULONG ulPlaintextLen, CK_BYTE_PTR pCiphertext,
    CK_ULONG_PTR pulCiphertextLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_EncryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
    CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_EncryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
    CK_ULONG ulParameterLen, CK_BYTE_PTR pPlaintextPart, CK_ULONG ulPlaintextPartLen,
    CK_BYTE_PTR pCiphertextPart, CK_ULONG_PTR pulCiphertextPartLen, CK_FLAGS flags)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_MessageEncryptFinal(CK_SESSION_HANDLE hSession)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_MessageDecryptInit(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_DecryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
    CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen,
    CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext,
    CK_ULONG_PTR pulPlaintextLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_DecryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
    CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_DecryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
    CK_ULONG ulParameterLen, CK_BYTE_PTR pCiphertextPart, CK_ULONG ulCiphertextPartLen,
    CK_BYTE_PTR pPlaintextPart, CK_ULONG_PTR pulPlaintextPartLen, CK_FLAGS flags)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_MessageDecryptFinal(CK_SESSION_HANDLE hSession)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_MessageSignInit(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_SignMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
    CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_SignMessageBegin(
    CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_SignMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
    CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_MessageSignFinal(CK_SESSION_HANDLE hSession)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_MessageVerifyInit(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_VerifyMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
    CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_VerifyMessageBegin(
    CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_VerifyMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
    CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_MessageVerifyFinal(CK_SESSION_HANDLE hSession)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_EncapsulateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hPublicKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
    CK_BYTE_PTR pCiphertext, CK_ULONG_PTR pulCiphertextLen, CK_OBJECT_HANDLE_PTR phKey)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_DecapsulateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hPrivateKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
    CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen, CK_OBJECT_HANDLE_PTR phKey)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_VerifySignatureInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_VerifySignature(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_VerifySignatureUpdate(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_VerifySignatureFinal(CK_SESSION_HANDLE hSession)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_GetSessionValidationFlags(
    CK_SESSION_HANDLE hSession, CK_SESSION_VALIDATION_FLAGS_TYPE type, CK_FLAGS_PTR pFlags)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_AsyncComplete(
    CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName, CK_ASYNC_DATA_PTR pResult)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_AsyncGetID(
    CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName, CK_ULONG_PTR pulID)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_AsyncJoin(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName,
    CK_ULONG ulID, CK_BYTE_PTR pData, CK_ULONG ulData)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_WrapKeyAuthenticated(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
    CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pWrappedKey,
    CK_ULONG_PTR pulWrappedKeyLen)
{
    return hsm::unsupportedOperation();
}

CK_EXPORT CK_RV CK_CALL C_UnwrapKeyAuthenticated(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
    CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
    CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_OBJECT_HANDLE_PTR phKey)
{
    return hsm::unsupportedOperation();
}
