// Export definitions are included after the internal implementation.
// Every entry point has its actual prototype, including unsupported operations.
template<class F> CK_RV boundary(bool needsInit,F&& fn) noexcept {
 try {
  std::scoped_lock lock(g.mutex);
  if(needsInit&&!g.initialized)return CKR_CRYPTOKI_NOT_INITIALIZED;
  return fn();
 }catch(const std::bad_alloc&){return CKR_HOST_MEMORY;}
 catch(const std::filesystem::filesystem_error&){return CKR_DEVICE_ERROR;}
 catch(...){return CKR_GENERAL_ERROR;}
}
CK_EXPORT CK_RV CK_CALL C_Initialize(CK_VOID_PTR pInitArgs) {
 return boundary(false,[&]()->CK_RV{return Initialize(pInitArgs);});
}
CK_EXPORT CK_RV CK_CALL C_Finalize(CK_VOID_PTR pReserved) {
 return boundary(true,[&]()->CK_RV{return Finalize(pReserved);});
}
CK_EXPORT CK_RV CK_CALL C_GetInfo(CK_INFO_PTR pInfo) {
 return boundary(true,[&]()->CK_RV{return GetInfo(pInfo);});
}
CK_EXPORT CK_RV CK_CALL C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
 return boundary(true,[&]()->CK_RV{return GetSlotList(tokenPresent,pSlotList,pulCount);});
}
CK_EXPORT CK_RV CK_CALL C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
 return boundary(true,[&]()->CK_RV{return GetSlotInfo(slotID,pInfo);});
}
CK_EXPORT CK_RV CK_CALL C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
 return boundary(true,[&]()->CK_RV{return GetTokenInfo(slotID,pInfo);});
}
CK_EXPORT CK_RV CK_CALL C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
 return boundary(true,[&]()->CK_RV{return GetMechanismList(slotID,pMechanismList,pulCount);});
}
CK_EXPORT CK_RV CK_CALL C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
 return boundary(true,[&]()->CK_RV{return GetMechanismInfo(slotID,type,pInfo);});
}
CK_EXPORT CK_RV CK_CALL C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
 return boundary(true,[&]()->CK_RV{return OpenSession(slotID,flags,pApplication,Notify,phSession);});
}
CK_EXPORT CK_RV CK_CALL C_CloseSession(CK_SESSION_HANDLE hSession) {
 return boundary(true,[&]()->CK_RV{return CloseSession(hSession);});
}
CK_EXPORT CK_RV CK_CALL C_CloseAllSessions(CK_SLOT_ID slotID) {
 return boundary(true,[&]()->CK_RV{return CloseAllSessions(slotID);});
}
CK_EXPORT CK_RV CK_CALL C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
 return boundary(true,[&]()->CK_RV{return GetSessionInfo(hSession,pInfo);});
}
CK_EXPORT CK_RV CK_CALL C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
 return boundary(true,[&]()->CK_RV{return Login(hSession,userType,pPin,ulPinLen);});
}
CK_EXPORT CK_RV CK_CALL C_Logout(CK_SESSION_HANDLE hSession) {
 return boundary(true,[&]()->CK_RV{return Logout(hSession);});
}
CK_EXPORT CK_RV CK_CALL C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
 return boundary(true,[&]()->CK_RV{return DestroyObject(hSession,hObject);});
}
CK_EXPORT CK_RV CK_CALL C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
 return boundary(true,[&]()->CK_RV{return GetAttributeValue(hSession,hObject,pTemplate,ulCount);});
}
CK_EXPORT CK_RV CK_CALL C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
 return boundary(true,[&]()->CK_RV{return FindInit(hSession,pTemplate,ulCount);});
}
CK_EXPORT CK_RV CK_CALL C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
 return boundary(true,[&]()->CK_RV{return Find(hSession,phObject,ulMaxObjectCount,pulObjectCount);});
}
CK_EXPORT CK_RV CK_CALL C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
 return boundary(true,[&]()->CK_RV{return FindFinal(hSession);});
}
CK_EXPORT CK_RV CK_CALL C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
 return boundary(true,[&]()->CK_RV{return SignInit(hSession,pMechanism,hKey);});
}
CK_EXPORT CK_RV CK_CALL C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
 return boundary(true,[&]()->CK_RV{return Sign(hSession,pData,ulDataLen,pSignature,pulSignatureLen);});
}
CK_EXPORT CK_RV CK_CALL C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
 return boundary(true,[&]()->CK_RV{return SignUpdate(hSession,pPart,ulPartLen);});
}
CK_EXPORT CK_RV CK_CALL C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
 return boundary(true,[&]()->CK_RV{return SignFinal(hSession,pSignature,pulSignatureLen);});
}
CK_EXPORT CK_RV CK_CALL C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
 return boundary(true,[&]()->CK_RV{return VerifyInit(hSession,pMechanism,hKey);});
}
CK_EXPORT CK_RV CK_CALL C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
 return boundary(true,[&]()->CK_RV{return Verify(hSession,pData,ulDataLen,pSignature,ulSignatureLen);});
}
CK_EXPORT CK_RV CK_CALL C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
 return boundary(true,[&]()->CK_RV{return VerifyUpdate(hSession,pPart,ulPartLen);});
}
CK_EXPORT CK_RV CK_CALL C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
 return boundary(true,[&]()->CK_RV{return VerifyFinal(hSession,pSignature,ulSignatureLen);});
}
CK_EXPORT CK_RV CK_CALL C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
 return boundary(true,[&]()->CK_RV{return GenerateKey(hSession,pMechanism,pTemplate,ulCount,phKey);});
}
CK_EXPORT CK_RV CK_CALL C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
 return boundary(true,[&]()->CK_RV{return GenerateKeyPair(hSession,pMechanism,pPublicKeyTemplate,ulPublicKeyAttributeCount,pPrivateKeyTemplate,ulPrivateKeyAttributeCount,phPublicKey,phPrivateKey);});
}
CK_EXPORT CK_RV CK_CALL C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
 return boundary(true,[&]()->CK_RV{return WrapKey(hSession,pMechanism,hWrappingKey,hKey,pWrappedKey,pulWrappedKeyLen);});
}
CK_EXPORT CK_RV CK_CALL C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
 return boundary(true,[&]()->CK_RV{return UnwrapKey(hSession,pMechanism,hUnwrappingKey,pWrappedKey,ulWrappedKeyLen,pTemplate,ulAttributeCount,phKey);});
}
CK_EXPORT CK_RV CK_CALL C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
 return boundary(true,[&]()->CK_RV{return DeriveKey(hSession,pMechanism,hBaseKey,pTemplate,ulAttributeCount,phKey);});
}
CK_EXPORT CK_RV CK_CALL C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen) {
 return boundary(true,[&]()->CK_RV{return GenerateRandom(hSession,RandomData,ulRandomLen);});
}
CK_EXPORT CK_RV CK_CALL C_GetFunctionStatus(CK_SESSION_HANDLE hSession) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_CancelFunction(CK_SESSION_HANDLE hSession) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pRserved) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_LoginUser(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_MessageEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_EncryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pPlaintext, CK_ULONG ulPlaintextLen, CK_BYTE_PTR pCiphertext, CK_ULONG_PTR pulCiphertextLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_EncryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_EncryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pPlaintextPart, CK_ULONG ulPlaintextPartLen, CK_BYTE_PTR pCiphertextPart, CK_ULONG_PTR pulCiphertextPartLen, CK_FLAGS flags) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_MessageEncryptFinal(CK_SESSION_HANDLE hSession) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_MessageDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_DecryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext, CK_ULONG_PTR pulPlaintextLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_DecryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_DecryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pCiphertextPart, CK_ULONG ulCiphertextPartLen, CK_BYTE_PTR pPlaintextPart, CK_ULONG_PTR pulPlaintextPartLen, CK_FLAGS flags) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_MessageDecryptFinal(CK_SESSION_HANDLE hSession) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_MessageSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_SignMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_SignMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_SignMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_MessageSignFinal(CK_SESSION_HANDLE hSession) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_MessageVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_VerifyMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_VerifyMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_VerifyMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_MessageVerifyFinal(CK_SESSION_HANDLE hSession) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_EncapsulateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hPublicKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_BYTE_PTR pCiphertext, CK_ULONG_PTR pulCiphertextLen, CK_OBJECT_HANDLE_PTR phKey) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_DecapsulateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hPrivateKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen, CK_OBJECT_HANDLE_PTR phKey) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_VerifySignatureInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_VerifySignature(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_VerifySignatureUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_VerifySignatureFinal(CK_SESSION_HANDLE hSession) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_GetSessionValidationFlags(CK_SESSION_HANDLE hSession, CK_SESSION_VALIDATION_FLAGS_TYPE type, CK_FLAGS_PTR pFlags) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_AsyncComplete(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName, CK_ASYNC_DATA_PTR pResult) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_AsyncGetID(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName, CK_ULONG_PTR pulID) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_AsyncJoin(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName, CK_ULONG ulID, CK_BYTE_PTR pData, CK_ULONG ulData) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_WrapKeyAuthenticated(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}
CK_EXPORT CK_RV CK_CALL C_UnwrapKeyAuthenticated(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_OBJECT_HANDLE_PTR phKey) {
 return boundary(true,[&]()->CK_RV{return CKR_FUNCTION_NOT_SUPPORTED;});
}

static CK_FUNCTION_LIST functions=[] {
 CK_FUNCTION_LIST table{};table.version={2,40};
#define CK_PKCS11_2_0_ONLY
#define CK_PKCS11_FUNCTION_INFO(name) table.name=name;
#include "oasis/pkcs11f.h"
#undef CK_PKCS11_FUNCTION_INFO
#undef CK_PKCS11_2_0_ONLY
 return table;
}();
static CK_FUNCTION_LIST_3_0 functions30=[] {
 CK_FUNCTION_LIST_3_0 table{};table.version={3,0};
#define CK_PKCS11_3_0_ONLY
#define CK_PKCS11_FUNCTION_INFO(name) table.name=name;
#include "oasis/pkcs11f.h"
#undef CK_PKCS11_FUNCTION_INFO
#undef CK_PKCS11_3_0_ONLY
 return table;
}();
static CK_FUNCTION_LIST_3_2 functions32=[] {
 CK_FUNCTION_LIST_3_2 table{};table.version={3,2};
#define CK_PKCS11_FUNCTION_INFO(name) table.name=name;
#include "oasis/pkcs11f.h"
#undef CK_PKCS11_FUNCTION_INFO
 return table;
}();
static CK_UTF8CHAR interfaceName[]="PKCS 11";
static CK_INTERFACE interfaces[]={
 {interfaceName,&functions32,0},{interfaceName,&functions30,0},{interfaceName,&functions,0}
};
CK_EXPORT CK_RV CK_CALL C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR p){
 if(!p)return CKR_ARGUMENTS_BAD;*p=&functions;return CKR_OK;
}
CK_EXPORT CK_RV CK_CALL C_GetInterfaceList(CK_INTERFACE_PTR out,CK_ULONG_PTR count){
 if(!count)return CKR_ARGUMENTS_BAD;
 constexpr CK_ULONG size=sizeof interfaces/sizeof interfaces[0];
 if(!out){*count=size;return CKR_OK;}
 if(*count<size){*count=size;return CKR_BUFFER_TOO_SMALL;}
 std::copy(std::begin(interfaces),std::end(interfaces),out);*count=size;return CKR_OK;
}
CK_EXPORT CK_RV CK_CALL C_GetInterface(CK_UTF8CHAR_PTR name,CK_VERSION_PTR version,CK_INTERFACE_PTR_PTR out,CK_FLAGS flags){
 if(!out)return CKR_ARGUMENTS_BAD;
 if(flags||(name&&std::strcmp(reinterpret_cast<const char*>(name),"PKCS 11")!=0))return CKR_ARGUMENTS_BAD;
 for(auto& item:interfaces){
  const auto* v=static_cast<const CK_VERSION*>(item.pFunctionList);
  if(!version||(version->major==v->major&&version->minor==v->minor)){*out=&item;return CKR_OK;}
 }
 return CKR_ARGUMENTS_BAD;
}
