#include "pkcs11.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdlib>
#include <iostream>
#include <vector>
int main(){
 CK_FUNCTION_LIST_PTR f=nullptr; assert(C_GetFunctionList(&f)==CKR_OK); assert(f&&f->version.major==2&&f->version.minor==40);
 assert(f->C_Initialize(nullptr)==CKR_OK);
 CK_ULONG n=0; assert(f->C_GetSlotList(CK_TRUE,nullptr,&n)==CKR_OK&&n==1); CK_SLOT_ID slot=0; assert(f->C_GetSlotList(CK_TRUE,&slot,&n)==CKR_OK&&slot==1);
 CK_SESSION_HANDLE s=0; assert(f->C_OpenSession(1,CKF_SERIAL_SESSION|CKF_RW_SESSION,nullptr,nullptr,&s)==CKR_OK);
 CK_MECHANISM aesGen{CKM_AES_KEY_GEN,nullptr,0}; CK_ULONG len=32; const char aesLabel[]="smoke-aes";
 CK_ATTRIBUTE aesAttrs[]={{CKA_LABEL,(void*)aesLabel,sizeof(aesLabel)-1},{CKA_VALUE_LEN,&len,sizeof(len)}}; CK_OBJECT_HANDLE aes=0;
 assert(f->C_GenerateKey(s,&aesGen,aesAttrs,2,&aes)==CKR_OK&&aes);
 CK_MECHANISM rsaGen{CKM_RSA_PKCS_KEY_PAIR_GEN,nullptr,0}; CK_ULONG bits=2048; const char rsaLabel[]="smoke-rsa";
 CK_ATTRIBUTE rsaAttrs[]={{CKA_LABEL,(void*)rsaLabel,sizeof(rsaLabel)-1},{CKA_MODULUS_BITS,&bits,sizeof(bits)}}; CK_OBJECT_HANDLE pub=0,priv=0;
 assert(f->C_GenerateKeyPair(s,&rsaGen,rsaAttrs,2,rsaAttrs,1,&pub,&priv)==CKR_OK&&pub&&priv);
 const CK_BYTE message[]="test message"; CK_MECHANISM signMech{CKM_SHA256_RSA_PKCS,nullptr,0};
 assert(f->C_SignInit(s,&signMech,priv)==CKR_OK); CK_ULONG sigLen=0; assert(f->C_Sign(s,(CK_BYTE_PTR)message,sizeof(message)-1,nullptr,&sigLen)==CKR_OK&&sigLen>0);
 std::vector<CK_BYTE> sig(sigLen); assert(f->C_Sign(s,(CK_BYTE_PTR)message,sizeof(message)-1,sig.data(),&sigLen)==CKR_OK);
 assert(f->C_VerifyInit(s,&signMech,pub)==CKR_OK); assert(f->C_Verify(s,(CK_BYTE_PTR)message,sizeof(message)-1,sig.data(),sigLen)==CKR_OK);
 CK_MECHANISM wrapMech{CKM_AES_KEY_WRAP_PAD,nullptr,0}; CK_ULONG wrappedLen=0; assert(f->C_WrapKey(s,&wrapMech,aes,priv,nullptr,&wrappedLen)==CKR_OK&&wrappedLen>0);
 std::vector<CK_BYTE> wrapped(wrappedLen); assert(f->C_WrapKey(s,&wrapMech,aes,priv,wrapped.data(),&wrappedLen)==CKR_OK);
 const char unwrappedLabel[]="smoke-unwrapped-rsa"; CK_OBJECT_CLASS privateClass=CKO_PRIVATE_KEY;
 CK_ATTRIBUTE unwrapAttrs[]={{CKA_CLASS,&privateClass,sizeof(privateClass)},{CKA_LABEL,(void*)unwrappedLabel,sizeof(unwrappedLabel)-1}}; CK_OBJECT_HANDLE unwrapped=0;
 assert(f->C_UnwrapKey(s,&wrapMech,aes,wrapped.data(),wrappedLen,unwrapAttrs,2,&unwrapped)==CKR_OK&&unwrapped);
 assert(f->C_CloseSession(s)==CKR_OK); assert(f->C_Finalize(nullptr)==CKR_OK); std::cout<<"PKCS#11 smoke test passed\n";
}
