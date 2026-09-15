#include "pkcs11.h"
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <vector>

static unsigned checks=0;
#define CHECK(x) do {++checks;if(!(x))throw std::runtime_error(#x);} while(false)
static CK_FUNCTION_LIST_PTR f;
static CK_SESSION_HANDLE session;

static void exercise(CK_MECHANISM_TYPE gen, CK_MECHANISM_TYPE mechanism,
                     const char* label, const std::vector<unsigned char>& curve,
                     size_t expectedSize) {
 CK_MECHANISM kg{gen,nullptr,0}, sigMechanism{mechanism,nullptr,0};
 CK_ULONG bits=2048;
 CK_ATTRIBUTE attrs[]={{CKA_LABEL,(void*)label,(CK_ULONG)std::char_traits<char>::length(label)},
 {CKA_MODULUS_BITS,&bits,sizeof bits},
 {CKA_EC_PARAMS,(void*)curve.data(),(CK_ULONG)curve.size()}};
 CK_OBJECT_HANDLE pub=0,priv=0;
 CHECK(f->C_GenerateKeyPair(session,&kg,attrs,3,attrs,1,&pub,&priv)==CKR_OK);
 CHECK(f->C_SignInit(session,&sigMechanism,pub)==CKR_KEY_TYPE_INCONSISTENT);
 CHECK(f->C_SignInit(session,&sigMechanism,priv)==CKR_OK);
 CHECK(f->C_SignInit(session,&sigMechanism,priv)==CKR_OPERATION_ACTIVE);
 unsigned char data[32]={1,2,3,4};
 CK_ULONG n=0;
 CHECK(f->C_Sign(session,data,sizeof data,nullptr,&n)==CKR_OK);
 CHECK(n==expectedSize);
 std::vector<unsigned char> signature(n);
 CK_ULONG small=1;
 CHECK(f->C_Sign(session,data,sizeof data,signature.data(),&small)==CKR_BUFFER_TOO_SMALL);
 CHECK(small==n);
 CHECK(f->C_Sign(session,data,sizeof data,signature.data(),&n)==CKR_OK);
 CHECK(f->C_Sign(session,data,sizeof data,signature.data(),&n)==CKR_OPERATION_NOT_INITIALIZED);
 CHECK(f->C_VerifyInit(session,&sigMechanism,pub)==CKR_OK);
 CHECK(f->C_Verify(session,data,sizeof data,signature.data(),n)==CKR_OK);
 signature[0]^=1;
 CHECK(f->C_VerifyInit(session,&sigMechanism,pub)==CKR_OK);
 CHECK(f->C_Verify(session,data,sizeof data,signature.data(),n)==CKR_SIGNATURE_INVALID);
 signature[0]^=1;
 CK_ULONG attrLen=0;
 CK_ATTRIBUTE attr{gen==CKM_EC_KEY_PAIR_GEN?CKA_EC_POINT:CKA_MODULUS,nullptr,0};
 CHECK(f->C_GetAttributeValue(session,pub,&attr,1)==CKR_OK);
 attrLen=attr.ulValueLen;CHECK(attrLen>0);
 // Independent EVP verification for raw RSA (detects accidental rehashing).
 {
  auto path=std::filesystem::path(std::getenv("HSM_SIM_DATA_DIR"))/"asymmetric"/(std::string(label)+".p12");
  FILE* in=std::fopen(path.string().c_str(),"rb");CHECK(in);
  PKCS12* p12=d2i_PKCS12_fp(in,nullptr);std::fclose(in);CHECK(p12);
  EVP_PKEY* key=nullptr;X509* cert=nullptr;CHECK(PKCS12_parse(p12,"",&key,&cert,nullptr)==1);
  EVP_PKEY_CTX* ctx=EVP_PKEY_CTX_new(key,nullptr);CHECK(ctx);
  std::vector<unsigned char> externalSig=signature;
  if(gen==CKM_EC_KEY_PAIR_GEN){
   auto width=signature.size()/2;
   ECDSA_SIG* pair=ECDSA_SIG_new();CHECK(pair);
   CHECK(ECDSA_SIG_set0(pair,BN_bin2bn(signature.data(),(int)width,nullptr),
                              BN_bin2bn(signature.data()+width,(int)width,nullptr))==1);
   externalSig.resize(i2d_ECDSA_SIG(pair,nullptr));auto p=externalSig.data();
   CHECK(i2d_ECDSA_SIG(pair,&p)>0);ECDSA_SIG_free(pair);
  }
  if(mechanism==CKM_ECDSA_SHA256){
   EVP_MD_CTX* md=EVP_MD_CTX_new();CHECK(md);
   CHECK(EVP_DigestVerifyInit(md,nullptr,EVP_sha256(),nullptr,key)==1);
   CHECK(EVP_DigestVerify(md,externalSig.data(),externalSig.size(),data,sizeof data)==1);
   EVP_MD_CTX_free(md);
  }else{
   CHECK(EVP_PKEY_verify_init(ctx)==1);
   if(gen==CKM_RSA_PKCS_KEY_PAIR_GEN)CHECK(EVP_PKEY_CTX_set_rsa_padding(ctx,RSA_PKCS1_PADDING)==1);
   CHECK(EVP_PKEY_verify(ctx,externalSig.data(),externalSig.size(),data,sizeof data)==1);
  }
  EVP_PKEY_CTX_free(ctx);EVP_PKEY_free(key);X509_free(cert);PKCS12_free(p12);
 }
 if(mechanism==CKM_ECDSA_SHA256){
  CHECK(f->C_SignInit(session,&sigMechanism,priv)==CKR_OK);
  CHECK(f->C_SignUpdate(session,data,7)==CKR_OK);
  CHECK(f->C_SignUpdate(session,data+7,sizeof data-7)==CKR_OK);
  n=0;CHECK(f->C_SignFinal(session,nullptr,&n)==CKR_OK);CHECK(n==expectedSize);
  n=1;CHECK(f->C_SignFinal(session,signature.data(),&n)==CKR_BUFFER_TOO_SMALL);
  CHECK(f->C_SignFinal(session,signature.data(),&n)==CKR_OK);
  CHECK(f->C_VerifyInit(session,&sigMechanism,pub)==CKR_OK);
  CHECK(f->C_Verify(session,data,sizeof data,signature.data(),n)==CKR_OK);
 }
 // A duplicate label must not overwrite existing key material.
 CK_OBJECT_HANDLE p2=0,q2=0;
 CHECK(f->C_GenerateKeyPair(session,&kg,attrs,3,attrs,1,&p2,&q2)==CKR_TEMPLATE_INCONSISTENT);
}
int main(){
 try{
  CHECK(std::getenv("HSM_SIM_DATA_DIR")!=nullptr);
  CHECK(C_GetFunctionList(&f)==CKR_OK);
  CHECK(f->C_Initialize(nullptr)==CKR_OK);
  CHECK(f->C_OpenSession(1,CKF_SERIAL_SESSION|CKF_RW_SESSION,nullptr,nullptr,&session)==CKR_OK);
  exercise(CKM_RSA_PKCS_KEY_PAIR_GEN,CKM_RSA_PKCS,"raw-rsa",{},256);
  exercise(CKM_EC_KEY_PAIR_GEN,CKM_ECDSA,"raw-ec",{6,8,0x2A,0x86,0x48,0xCE,0x3D,3,1,7},64);
  exercise(CKM_EC_KEY_PAIR_GEN,CKM_ECDSA_SHA256,"hash-ec",{6,5,0x2B,0x81,4,0,0x22},96);
  CHECK(f->C_Finalize(nullptr)==CKR_OK);
  CHECK(f->C_Initialize(nullptr)==CKR_OK);
  CHECK(f->C_OpenSession(1,CKF_SERIAL_SESSION,nullptr,nullptr,&session)==CKR_OK);
  CHECK(f->C_FindObjectsInit(session,nullptr,0)==CKR_OK);
  CK_OBJECT_HANDLE objects[16];CK_ULONG n=0;
  CHECK(f->C_FindObjects(session,objects,16,&n)==CKR_OK);CHECK(n==6);
  CHECK(f->C_FindObjectsFinal(session)==CKR_OK);
  CHECK(f->C_Finalize(nullptr)==CKR_OK);
  std::cout<<checks<<" regression checks passed\n";return 0;
 }catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<"\n";return 1;}
}
