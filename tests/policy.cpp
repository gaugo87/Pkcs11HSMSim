#include "pkcs11.h"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
static unsigned checks=0;
#define CHECK(x) do{++checks;if(!(x))throw std::runtime_error(#x);}while(false)
static CK_FUNCTION_LIST_PTR f;
static CK_SESSION_HANDLE s;
static CK_BBOOL yes=CK_TRUE,no=CK_FALSE;
static CK_RV set(CK_OBJECT_HANDLE h,CK_ATTRIBUTE_TYPE t,CK_BBOOL value){CK_ATTRIBUTE a{t,&value,sizeof value};return f->C_SetAttributeValue(s,h,&a,1);}
static bool get(CK_OBJECT_HANDLE h,CK_ATTRIBUTE_TYPE t){CK_BBOOL value=99;CK_ATTRIBUTE a{t,&value,sizeof value};CHECK(f->C_GetAttributeValue(s,h,&a,1)==CKR_OK);return value!=0;}
static CK_OBJECT_HANDLE find(std::string label,CK_OBJECT_CLASS cls){
 CK_ATTRIBUTE a[]={{CKA_LABEL,label.data(),(CK_ULONG)label.size()},{CKA_CLASS,&cls,sizeof cls}};
 CHECK(f->C_FindObjectsInit(s,a,2)==CKR_OK);CK_OBJECT_HANDLE h[2];CK_ULONG n=0;
 CHECK(f->C_FindObjects(s,h,2,&n)==CKR_OK);CHECK(f->C_FindObjectsFinal(s)==CKR_OK);CHECK(n==1);return h[0];
}
static CK_OBJECT_HANDLE aes(std::string label,bool token=true){
 CK_MECHANISM m{CKM_AES_KEY_GEN,nullptr,0};CK_ULONG n=32;CK_BBOOL persistent=token;
 CK_ATTRIBUTE a[]={{CKA_LABEL,label.data(),(CK_ULONG)label.size()},{CKA_VALUE_LEN,&n,sizeof n},{CKA_TOKEN,&persistent,sizeof persistent},
 {CKA_DERIVE,&no,sizeof no},{CKA_WRAP,&no,sizeof no},{CKA_UNWRAP,&no,sizeof no}};
 CK_OBJECT_HANDLE h;CHECK(f->C_GenerateKey(s,&m,a,6,&h)==CKR_OK);return h;
}
static void open(){CHECK(f->C_Initialize(nullptr)==CKR_OK);CHECK(f->C_OpenSession(1,CKF_SERIAL_SESSION|CKF_RW_SESSION,nullptr,nullptr,&s)==CKR_OK);}
int main(){try{
 auto env=std::getenv("HSM_SIM_DATA_DIR");CHECK(env&&*env);std::filesystem::path root(env);
 CHECK(!std::filesystem::exists(root)||std::filesystem::is_empty(root));
 std::filesystem::create_directories(root/"symmetric");
 std::ofstream(root/"symmetric"/"legacy.key")<<"00112233445566778899AABBCCDDEEFF\n";
 {std::ofstream old(root/"symmetric"/"legacy.key.meta",std::ios::binary);
  const unsigned char bytes[]={0x48,0x53,0x4d,0x31,0,0,0,1,0,0,0,4,0,0,0,6,'l','e','g','a','c','y',0,0,0,1,42};
  old.write(reinterpret_cast<const char*>(bytes),sizeof bytes);}
 CHECK(C_GetFunctionList(&f)==CKR_OK);open();
 auto legacy=find("legacy",CKO_SECRET_KEY);CHECK(get(legacy,CKA_WRAP));CHECK(set(legacy,CKA_WRAP,no)==CKR_OK);
 auto master=aes("master"),payload=aes("payload");
 CHECK(!get(master,CKA_DERIVE));CHECK(!get(master,CKA_WRAP));CHECK(!get(master,CKA_UNWRAP));
 unsigned char context[32]={1,2,3};CK_KEY_DERIVATION_STRING_DATA data{context,sizeof context};
 CK_MECHANISM derive{CKM_AES_ECB_ENCRYPT_DATA,&data,sizeof data};CK_KEY_TYPE type=CKK_AES;CK_ULONG length=16;
 CK_ATTRIBUTE attrs[]={{CKA_KEY_TYPE,&type,sizeof type},{CKA_VALUE_LEN,&length,sizeof length},{CKA_TOKEN,&no,sizeof no},
 {CKA_WRAP,&yes,sizeof yes},{CKA_UNWRAP,&yes,sizeof yes},{CKA_SENSITIVE,&yes,sizeof yes},{CKA_EXTRACTABLE,&no,sizeof no}};
 CK_OBJECT_HANDLE wrapping=0;CHECK(f->C_DeriveKey(s,&derive,master,attrs,7,&wrapping)==CKR_KEY_FUNCTION_NOT_PERMITTED);
 CHECK(set(master,CKA_DERIVE,yes)==CKR_OK);CHECK(f->C_DeriveKey(s,&derive,master,attrs,7,&wrapping)==CKR_OK);
 CHECK(get(wrapping,CKA_WRAP));CHECK(get(wrapping,CKA_UNWRAP));CHECK(get(wrapping,CKA_SENSITIVE));CHECK(!get(wrapping,CKA_EXTRACTABLE));
 CK_ATTRIBUTE secret{CKA_VALUE,nullptr,0};CHECK(f->C_GetAttributeValue(s,wrapping,&secret,1)==CKR_ATTRIBUTE_SENSITIVE);CHECK(secret.ulValueLen==CK_UNAVAILABLE_INFORMATION);
 CHECK(f->C_GetAttributeValue(s,payload,&secret,1)==CKR_OK);CHECK(secret.ulValueLen==32);
 CHECK(set(payload,CKA_SENSITIVE,yes)==CKR_OK);
 CK_MECHANISM wrap{CKM_AES_KEY_WRAP_PAD,nullptr,0};CK_ULONG n=0;
 CHECK(f->C_WrapKey(s,&wrap,master,payload,nullptr,&n)==CKR_KEY_FUNCTION_NOT_PERMITTED);
 CHECK(f->C_WrapKey(s,&wrap,wrapping,payload,nullptr,&n)==CKR_OK);std::vector<unsigned char> blob(n);
 CHECK(f->C_WrapKey(s,&wrap,wrapping,payload,blob.data(),&n)==CKR_OK);
 CHECK(set(payload,CKA_EXTRACTABLE,no)==CKR_OK);CHECK(f->C_WrapKey(s,&wrap,wrapping,payload,nullptr,&n)==CKR_KEY_UNEXTRACTABLE);
 CHECK(set(payload,CKA_EXTRACTABLE,yes)==CKR_ATTRIBUTE_READ_ONLY);CHECK(set(payload,CKA_SENSITIVE,no)==CKR_ATTRIBUTE_READ_ONLY);
 CK_ATTRIBUTE unattrs[]={{CKA_TOKEN,&no,sizeof no},{CKA_WRAP,&no,sizeof no},{CKA_DERIVE,&no,sizeof no},{CKA_EXTRACTABLE,&no,sizeof no}};
 CK_OBJECT_HANDLE restored;CHECK(set(wrapping,CKA_UNWRAP,no)==CKR_OK);
 CHECK(f->C_UnwrapKey(s,&wrap,wrapping,blob.data(),(CK_ULONG)blob.size(),unattrs,4,&restored)==CKR_KEY_FUNCTION_NOT_PERMITTED);
 CHECK(set(wrapping,CKA_UNWRAP,yes)==CKR_OK);
 CHECK(f->C_UnwrapKey(s,&wrap,wrapping,blob.data(),(CK_ULONG)blob.size(),unattrs,4,&restored)==CKR_OK);
 CHECK(!get(restored,CKA_WRAP));CHECK(!get(restored,CKA_DERIVE));CHECK(!get(restored,CKA_TOKEN));
 CHECK(f->C_GetAttributeValue(s,restored,&secret,1)==CKR_ATTRIBUTE_SENSITIVE);
 // RSA policies affect Init and multipart completion after an intervening update.
 CK_MECHANISM rsa{CKM_RSA_PKCS_KEY_PAIR_GEN,nullptr,0},sign{CKM_SHA256_RSA_PKCS,nullptr,0};CK_ULONG bits=2048;
 char label[]="rsa";CK_ATTRIBUTE pubAttrs[]={{CKA_LABEL,label,3},{CKA_MODULUS_BITS,&bits,sizeof bits},{CKA_VERIFY,&no,sizeof no}};
 CK_ATTRIBUTE privAttrs[]={{CKA_LABEL,label,3},{CKA_SIGN,&no,sizeof no}};CK_OBJECT_HANDLE pub,priv;
 CHECK(f->C_GenerateKeyPair(s,&rsa,pubAttrs,3,privAttrs,2,&pub,&priv)==CKR_OK);
 CHECK(f->C_SignInit(s,&sign,priv)==CKR_KEY_FUNCTION_NOT_PERMITTED);CHECK(f->C_VerifyInit(s,&sign,pub)==CKR_KEY_FUNCTION_NOT_PERMITTED);
 CHECK(set(priv,CKA_SIGN,yes)==CKR_OK);CHECK(f->C_SignInit(s,&sign,priv)==CKR_OK);
 CHECK(f->C_SignUpdate(s,context,sizeof context)==CKR_OK);CHECK(set(priv,CKA_SIGN,no)==CKR_OK);
 unsigned char signature[256];CK_ULONG sn=sizeof signature;
 CHECK(f->C_SignFinal(s,signature,&sn)==CKR_KEY_FUNCTION_NOT_PERMITTED);
 CHECK(set(priv,CKA_SIGN,yes)==CKR_OK);CHECK(f->C_SignInit(s,&sign,priv)==CKR_OK);
 sn=sizeof signature;CHECK(f->C_Sign(s,context,sizeof context,signature,&sn)==CKR_OK);
 CHECK(set(pub,CKA_VERIFY,yes)==CKR_OK);CHECK(f->C_VerifyInit(s,&sign,pub)==CKR_OK);CHECK(f->C_Verify(s,context,sizeof context,signature,sn)==CKR_OK);
 CHECK(set(priv,CKA_SIGN,no)==CKR_OK);CHECK(set(pub,CKA_VERIFY,no)==CKR_OK);
 n=0;CHECK(f->C_WrapKey(s,&wrap,wrapping,priv,nullptr,&n)==CKR_OK);blob.resize(n);
 CHECK(f->C_WrapKey(s,&wrap,wrapping,priv,blob.data(),&n)==CKR_OK);
 CK_OBJECT_CLASS privateClass=CKO_PRIVATE_KEY;char unlabel[]="private-session";
 CK_ATTRIBUTE unprivate[]={{CKA_CLASS,&privateClass,sizeof privateClass},{CKA_TOKEN,&no,sizeof no},{CKA_LABEL,unlabel,sizeof unlabel-1},{CKA_SIGN,&no,sizeof no}};
 CK_OBJECT_HANDLE unpriv;CHECK(f->C_UnwrapKey(s,&wrap,wrapping,blob.data(),n,unprivate,4,&unpriv)==CKR_OK);
 CHECK(!get(unpriv,CKA_SIGN));CHECK(!get(unpriv,CKA_TOKEN));CHECK(!std::filesystem::exists(root/"asymmetric"/"private-session.p12"));
 CHECK(f->C_SignInit(s,&sign,unpriv)==CKR_KEY_FUNCTION_NOT_PERMITTED);
 CK_ATTRIBUTE sesspub[]={{CKA_TOKEN,&no,sizeof no},{CKA_MODULUS_BITS,&bits,sizeof bits}};
 CK_ATTRIBUTE sesspriv[]={{CKA_TOKEN,&no,sizeof no},{CKA_SIGN,&no,sizeof no}};CK_OBJECT_HANDLE sessionPub,sessionPriv;
 CHECK(f->C_GenerateKeyPair(s,&rsa,sesspub,2,sesspriv,2,&sessionPub,&sessionPriv)==CKR_OK);
 CHECK(!get(sessionPriv,CKA_TOKEN));CHECK(!get(sessionPub,CKA_TOKEN));CHECK(!get(sessionPriv,CKA_SIGN));
 CHECK(!std::filesystem::exists(root/"asymmetric"/"generated-key.p12"));
 // Rejected multi-attribute update must be atomic.
 CK_ATTRIBUTE bad[]={{CKA_WRAP,&yes,sizeof yes},{CKA_EXTRACTABLE,&yes,sizeof yes}};
 CHECK(f->C_SetAttributeValue(s,payload,bad,2)==CKR_ATTRIBUTE_READ_ONLY);CHECK(!get(payload,CKA_WRAP));
 CK_BBOOL invalid=2;CK_ATTRIBUTE malformed{CKA_WRAP,&invalid,sizeof invalid};
 CHECK(f->C_SetAttributeValue(s,payload,&malformed,1)==CKR_ATTRIBUTE_VALUE_INVALID);
 CHECK(f->C_GenerateKey(s,&rsa,nullptr,1,&restored)==CKR_MECHANISM_INVALID);
 CK_MECHANISM aesGen{CKM_AES_KEY_GEN,nullptr,0};CHECK(f->C_GenerateKey(s,&aesGen,&malformed,1,&restored)==CKR_ATTRIBUTE_VALUE_INVALID);
 // A failed metadata replacement must preserve both memory and key file.
 auto temp=root/"symmetric"/"master.key.meta.tmp";std::ofstream(temp)<<"occupied";
 CHECK(set(master,CKA_DERIVE,no)==CKR_DEVICE_ERROR);CHECK(get(master,CKA_DERIVE));
 CHECK(std::filesystem::exists(root/"symmetric"/"master.key"));std::filesystem::remove(temp);
 CK_SESSION_HANDLE ro;CHECK(f->C_OpenSession(1,CKF_SERIAL_SESSION,nullptr,nullptr,&ro)==CKR_OK);
 CK_ATTRIBUTE disable{CKA_DERIVE,&no,sizeof no};CHECK(f->C_SetAttributeValue(ro,master,&disable,1)==CKR_SESSION_READ_ONLY);
 CHECK(f->C_DestroyObject(ro,master)==CKR_SESSION_READ_ONLY);
 auto ephemeral=aes("ephemeral",false);CHECK(!std::filesystem::exists(root/"symmetric"/"ephemeral.key"));
 CHECK(set(ephemeral,CKA_DESTROYABLE,no)==CKR_OK);CHECK(f->C_DestroyObject(s,ephemeral)==CKR_ACTION_PROHIBITED);
 CHECK(set(ephemeral,CKA_MODIFIABLE,no)==CKR_OK);CHECK(set(ephemeral,CKA_WRAP,yes)==CKR_ACTION_PROHIBITED);
 CHECK(f->C_CloseSession(s)==CKR_OK);s=ro;CHECK(f->C_GetAttributeValue(s,ephemeral,&secret,1)==CKR_OBJECT_HANDLE_INVALID);
 CHECK(f->C_GetAttributeValue(s,wrapping,&secret,1)==CKR_OBJECT_HANDLE_INVALID);
 CHECK(f->C_GetAttributeValue(s,unpriv,&secret,1)==CKR_OBJECT_HANDLE_INVALID);
 CHECK(f->C_GetAttributeValue(s,sessionPriv,&secret,1)==CKR_OBJECT_HANDLE_INVALID);
 CHECK(f->C_Finalize(nullptr)==CKR_OK);open();
 master=find("master",CKO_SECRET_KEY);payload=find("payload",CKO_SECRET_KEY);priv=find("rsa",CKO_PRIVATE_KEY);pub=find("rsa",CKO_PUBLIC_KEY);
 CHECK(get(master,CKA_DERIVE));CHECK(!get(master,CKA_WRAP));CHECK(get(payload,CKA_SENSITIVE));CHECK(!get(payload,CKA_EXTRACTABLE));
 CHECK(!get(priv,CKA_SIGN));CHECK(!get(pub,CKA_VERIFY));CHECK(f->C_SignInit(s,&sign,priv)==CKR_KEY_FUNCTION_NOT_PERMITTED);
 legacy=find("legacy",CKO_SECRET_KEY);CHECK(!get(legacy,CKA_WRAP));
 // A public sibling must not allow deleting a protected private key's file.
 CHECK(set(priv,CKA_DESTROYABLE,no)==CKR_OK);CHECK(f->C_DestroyObject(s,pub)==CKR_ACTION_PROHIBITED);
 CHECK(f->C_Finalize(nullptr)==CKR_OK);
 std::cout<<checks<<" policy checks passed\n";return 0;
 }catch(const std::exception& e){std::cerr<<"FAIL after "<<checks<<": "<<e.what()<<'\n';return 1;}}
