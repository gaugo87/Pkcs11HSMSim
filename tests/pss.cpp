#include "pkcs11.h"
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <filesystem>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <array>
static unsigned checks=0;
#define CHECK(x) do {++checks;if(!(x))throw std::runtime_error(#x);} while(false)
int main(){
 try {
  CHECK(std::getenv("HSM_SIM_DATA_DIR"));
  CK_FUNCTION_LIST_PTR f=nullptr;CHECK(C_GetFunctionList(&f)==CKR_OK);
  CHECK(f->C_Initialize(nullptr)==CKR_OK);
  CK_SESSION_HANDLE session;CHECK(f->C_OpenSession(1,CKF_SERIAL_SESSION|CKF_RW_SESSION,nullptr,nullptr,&session)==CKR_OK);
  CK_MECHANISM kg{CKM_RSA_PKCS_KEY_PAIR_GEN,nullptr,0};
  char label[]="pss";CK_ULONG bits=2048;
  CK_ATTRIBUTE attrs[]={{CKA_LABEL,label,3},{CKA_MODULUS_BITS,&bits,sizeof bits}};
  CK_OBJECT_HANDLE pub,priv;CHECK(f->C_GenerateKeyPair(session,&kg,attrs,2,attrs,1,&pub,&priv)==CKR_OK);
  auto path=std::filesystem::path(std::getenv("HSM_SIM_DATA_DIR"))/"asymmetric"/"pss.p12";
  FILE* in=std::fopen(path.string().c_str(),"rb");CHECK(in);
  PKCS12* p12=d2i_PKCS12_fp(in,nullptr);std::fclose(in);CHECK(p12);
  EVP_PKEY* key=nullptr;X509* cert=nullptr;CHECK(PKCS12_parse(p12,"",&key,&cert,nullptr)==1);
  PKCS12_free(p12);X509_free(cert);
  struct Mode{CK_MECHANISM_TYPE mechanism,hash;CK_ULONG mgf;const EVP_MD* md;};
  const std::array<Mode,6> modes={{
   {CKM_RSA_PKCS_PSS,CKM_SHA256,CKG_MGF1_SHA256,EVP_sha256()},
   {CKM_RSA_PKCS_PSS,CKM_SHA384,CKG_MGF1_SHA384,EVP_sha384()},
   {CKM_RSA_PKCS_PSS,CKM_SHA512,CKG_MGF1_SHA512,EVP_sha512()},
   {CKM_SHA256_RSA_PKCS_PSS,CKM_SHA256,CKG_MGF1_SHA256,EVP_sha256()},
   {CKM_SHA384_RSA_PKCS_PSS,CKM_SHA384,CKG_MGF1_SHA384,EVP_sha384()},
   {CKM_SHA512_RSA_PKCS_PSS,CKM_SHA512,CKG_MGF1_SHA512,EVP_sha512()}}};
  unsigned char message[]="PSS independent interoperability test";
  for(auto mode:modes)for(CK_ULONG salt: {0UL,(CK_ULONG)EVP_MD_get_size(mode.md)}){
   CK_RSA_PKCS_PSS_PARAMS p{mode.hash,mode.mgf,salt};
   CK_MECHANISM m{mode.mechanism,&p,sizeof p};
   unsigned char hash[64];unsigned hashLen=0;
   CHECK(EVP_Digest(message,sizeof message,hash,&hashLen,mode.md,nullptr)==1);
   bool raw=mode.mechanism==CKM_RSA_PKCS_PSS;
   auto data=raw?hash:message;CK_ULONG dataLen=raw?hashLen:sizeof message;
   CHECK(f->C_SignInit(session,&m,priv)==CKR_OK);
   // Init must copy parameters: the client can release or modify its buffer.
   p.sLen=9999;
   CK_ULONG n=0;CHECK(f->C_Sign(session,data,dataLen,nullptr,&n)==CKR_OK);CHECK(n==256);
   std::vector<unsigned char> signature(n);
   CK_ULONG small=1;CHECK(f->C_Sign(session,data,dataLen,signature.data(),&small)==CKR_BUFFER_TOO_SMALL);
   CHECK(small==256);CHECK(f->C_Sign(session,data,dataLen,signature.data(),&n)==CKR_OK);
   EVP_PKEY_CTX* ctx=EVP_PKEY_CTX_new(key,nullptr);CHECK(ctx);
   CHECK(EVP_PKEY_verify_init(ctx)==1);
   CHECK(EVP_PKEY_CTX_set_rsa_padding(ctx,RSA_PKCS1_PSS_PADDING)==1);
   CHECK(EVP_PKEY_CTX_set_signature_md(ctx,mode.md)==1);
   CHECK(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx,mode.md)==1);
   CHECK(EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx,(int)salt)==1);
   CHECK(EVP_PKEY_verify(ctx,signature.data(),n,hash,hashLen)==1);
   EVP_PKEY_CTX_free(ctx);p.sLen=salt;
   CHECK(f->C_VerifyInit(session,&m,pub)==CKR_OK);
   CHECK(f->C_Verify(session,data,dataLen,signature.data(),n)==CKR_OK);
   signature[10]^=1;
   CHECK(f->C_VerifyInit(session,&m,pub)==CKR_OK);
   CHECK(f->C_Verify(session,data,dataLen,signature.data(),n)==CKR_SIGNATURE_INVALID);
   if(!raw){
    CHECK(f->C_SignInit(session,&m,priv)==CKR_OK);
    CHECK(f->C_SignUpdate(session,data,5)==CKR_OK);
    CHECK(f->C_SignUpdate(session,data+5,dataLen-5)==CKR_OK);
    CHECK(f->C_SignFinal(session,signature.data(),&n)==CKR_OK);
    CHECK(f->C_VerifyInit(session,&m,pub)==CKR_OK);
    CHECK(f->C_VerifyUpdate(session,data,3)==CKR_OK);
    CHECK(f->C_VerifyUpdate(session,data+3,dataLen-3)==CKR_OK);
    CHECK(f->C_VerifyFinal(session,signature.data(),n)==CKR_OK);
   }
  }
  CK_RSA_PKCS_PSS_PARAMS p{CKM_SHA256,CKG_MGF1_SHA256,32};
  CK_MECHANISM m{CKM_SHA256_RSA_PKCS_PSS,&p,sizeof p};
  p.hashAlg=CKM_SHA384;CHECK(f->C_SignInit(session,&m,priv)==CKR_MECHANISM_PARAM_INVALID);
  p.hashAlg=CKM_SHA256;p.mgf=9999;CHECK(f->C_SignInit(session,&m,priv)==CKR_MECHANISM_PARAM_INVALID);
  p.mgf=CKG_MGF1_SHA256;p.sLen=9999;CHECK(f->C_SignInit(session,&m,priv)==CKR_MECHANISM_PARAM_INVALID);
  p.sLen=32;m.ulParameterLen=1;CHECK(f->C_SignInit(session,&m,priv)==CKR_MECHANISM_PARAM_INVALID);
  m.ulParameterLen=sizeof p;m.pParameter=nullptr;CHECK(f->C_SignInit(session,&m,priv)==CKR_MECHANISM_PARAM_INVALID);
  m.pParameter=&p;m.mechanism=CKM_RSA_PKCS_PSS;
  CHECK(f->C_SignInit(session,&m,priv)==CKR_OK);
  unsigned char sig[256];CK_ULONG n=sizeof sig;
  CHECK(f->C_Sign(session,message,3,sig,&n)==CKR_DATA_LEN_RANGE);
  CHECK(f->C_SignInit(session,&m,priv)==CKR_OK);
  CHECK(f->C_SignUpdate(session,message,3)==CKR_MECHANISM_INVALID);
  EVP_PKEY_free(key);CHECK(f->C_Finalize(nullptr)==CKR_OK);
  std::cout<<checks<<" PSS checks passed\n";return 0;
 }catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<"\n";return 1;}
}
