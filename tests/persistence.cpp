#include "pkcs11.h"
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <string>
#include <filesystem>
static unsigned checks=0;
#define CHECK(x) do {++checks;if(!(x))throw std::runtime_error(#x);} while(false)
static CK_FUNCTION_LIST_PTR f;
static CK_SESSION_HANDLE s;
static std::vector<CK_OBJECT_HANDLE> find(CK_ATTRIBUTE* attrs,CK_ULONG n){
 CHECK(f->C_FindObjectsInit(s,attrs,n)==CKR_OK);
 CK_OBJECT_HANDLE handles[20];CK_ULONG count;
 CHECK(f->C_FindObjects(s,handles,20,&count)==CKR_OK);
 CHECK(f->C_FindObjectsFinal(s)==CKR_OK);
 return {handles,handles+count};
}
static std::string get(CK_OBJECT_HANDLE h,CK_ATTRIBUTE_TYPE type){
 CK_ATTRIBUTE a{type,nullptr,0};CHECK(f->C_GetAttributeValue(s,h,&a,1)==CKR_OK);
 std::string out(a.ulValueLen,'\0');a.pValue=out.data();
 CHECK(f->C_GetAttributeValue(s,h,&a,1)==CKR_OK);return out;
}
static void open(){
 CHECK(f->C_Initialize(nullptr)==CKR_OK);
 CHECK(f->C_OpenSession(1,CKF_SERIAL_SESSION|CKF_RW_SESSION,nullptr,nullptr,&s)==CKR_OK);
}
int main(){
 try{
  CHECK(std::getenv("HSM_SIM_DATA_DIR"));CHECK(C_GetFunctionList(&f)==CKR_OK);open();
  std::string publicLabel="public / signing key",privateLabel="private / signing key";
  unsigned char id[]={0,255,0,128,42};
  CK_ULONG bits=2048,len=32;
  CK_ATTRIBUTE pub[]={{CKA_LABEL,publicLabel.data(),(CK_ULONG)publicLabel.size()},{CKA_ID,id,sizeof id},{CKA_MODULUS_BITS,&bits,sizeof bits}};
  CK_ATTRIBUTE priv[]={{CKA_LABEL,privateLabel.data(),(CK_ULONG)privateLabel.size()}};
  CK_MECHANISM kg{CKM_RSA_PKCS_KEY_PAIR_GEN,nullptr,0};CK_OBJECT_HANDLE ph,qh;
  CHECK(f->C_GenerateKeyPair(s,&kg,pub,3,priv,1,&ph,&qh)==CKR_OK);
  std::string aesLabel="AES wrapping key";unsigned char aesId[]={1,0,2,0,3};
  CK_ATTRIBUTE aesAttrs[]={{CKA_LABEL,aesLabel.data(),(CK_ULONG)aesLabel.size()},{CKA_ID,aesId,sizeof aesId},{CKA_VALUE_LEN,&len,sizeof len}};
  CK_MECHANISM aesGen{CKM_AES_KEY_GEN,nullptr,0};CK_OBJECT_HANDLE aes;
  CHECK(f->C_GenerateKey(s,&aesGen,aesAttrs,3,&aes)==CKR_OK);
  for(int iteration=0;iteration<2;iteration++){
   CK_BBOOL yes=CK_TRUE;CK_OBJECT_CLASS cls=CKO_PRIVATE_KEY;
   CK_ATTRIBUTE filter[]={{CKA_ID,id,sizeof id},{CKA_TOKEN,&yes,sizeof yes}};
   auto both=find(filter,2);CHECK(both.size()==2);
   CHECK(get(aes,CKA_LABEL)==aesLabel);CHECK(get(aes,CKA_ID)==std::string((char*)aesId,sizeof aesId));
   CK_ATTRIBUTE onlyPrivate[]={{CKA_CLASS,&cls,sizeof cls},{CKA_SIGN,&yes,sizeof yes},{CKA_ID,id,sizeof id}};
   auto keys=find(onlyPrivate,3);CHECK(keys.size()==1);
   CHECK(get(keys[0],CKA_LABEL)==privateLabel);
   CHECK(get(keys[0],CKA_ID)==std::string((char*)id,sizeof id));
   cls=CKO_PUBLIC_KEY;onlyPrivate[1].type=CKA_VERIFY;
   keys=find(onlyPrivate,3);CHECK(keys.size()==1);CHECK(get(keys[0],CKA_LABEL)==publicLabel);
   CHECK(f->C_Finalize(nullptr)==CKR_OK);open();
   CK_ATTRIBUTE aesFilter{CKA_ID,aesId,sizeof aesId};keys=find(&aesFilter,1);CHECK(keys.size()==1);aes=keys[0];
  }
  CHECK(f->C_DestroyObject(s,aes)==CKR_OK);
  CHECK(!std::filesystem::exists(std::filesystem::path(std::getenv("HSM_SIM_DATA_DIR"))/"symmetric"/"AES_wrapping_key.key.meta"));
  CHECK(f->C_Finalize(nullptr)==CKR_OK);open();
  CK_ATTRIBUTE aesFilter{CKA_ID,aesId,sizeof aesId};CHECK(find(&aesFilter,1).empty());
  CHECK(f->C_Finalize(nullptr)==CKR_OK);
  std::cout<<checks<<" persistence checks passed\n";return 0;
 }catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<"\n";return 1;}
}
