#include "pkcs11.h"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <string>
static unsigned checks=0;
#define CHECK(x) do{++checks;if(!(x))throw std::runtime_error(#x);}while(false)
static CK_FUNCTION_LIST_PTR f;
static CK_SESSION_HANDLE s;
static CK_OBJECT_HANDLE find(std::string label){
 CK_ATTRIBUTE a{CKA_LABEL,label.data(),(CK_ULONG)label.size()};
 CHECK(f->C_FindObjectsInit(s,&a,1)==CKR_OK);
 CK_OBJECT_HANDLE h[2];CK_ULONG n=0;CHECK(f->C_FindObjects(s,h,2,&n)==CKR_OK);
 CHECK(f->C_FindObjectsFinal(s)==CKR_OK);CHECK(n==1);return h[0];
}
static std::string read(const std::filesystem::path& p){std::ifstream in(p);std::string value;in>>value;CHECK(in.good()||in.eof());return value;}
int main(){try{
 auto env=std::getenv("HSM_SIM_DATA_DIR");CHECK(env&&*env);std::filesystem::path root(env);
 CHECK(!std::filesystem::exists(root)||std::filesystem::is_empty(root));
 std::filesystem::create_directories(root/"symmetric");
 // NIST SP 800-38A F.1.1, first two AES-128 ECB blocks.
 std::ofstream(root/"symmetric"/"master.key")<<"2B7E151628AED2A6ABF7158809CF4F3C\n";
 unsigned char data[]={0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
 std::string expected="3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF";
 CHECK(C_GetFunctionList(&f)==CKR_OK);CHECK(f->C_Initialize(nullptr)==CKR_OK);
 CHECK(f->C_OpenSession(1,CKF_SERIAL_SESSION|CKF_RW_SESSION,nullptr,nullptr,&s)==CKR_OK);
 auto master=find("master");
 CK_MECHANISM_INFO info{};CHECK(f->C_GetMechanismInfo(1,CKM_AES_ECB_ENCRYPT_DATA,&info)==CKR_OK);CHECK(info.flags==CKF_DERIVE&&info.ulMinKeySize==16&&info.ulMaxKeySize==32);
 CK_KEY_DERIVATION_STRING_DATA input{data,sizeof data};CK_MECHANISM m{CKM_AES_ECB_ENCRYPT_DATA,&input,sizeof input};
 CK_KEY_TYPE type=CKK_AES;CK_ULONG len=32;CK_BBOOL token=CK_TRUE,yes=CK_TRUE;
 std::string label="derived";
 CK_ATTRIBUTE attrs[]={{CKA_KEY_TYPE,&type,sizeof type},{CKA_VALUE_LEN,&len,sizeof len},{CKA_TOKEN,&token,sizeof token},{CKA_LABEL,label.data(),(CK_ULONG)label.size()},{CKA_WRAP,&yes,sizeof yes},{CKA_UNWRAP,&yes,sizeof yes}};
 CK_OBJECT_HANDLE derived=0;
 for(auto size:{16UL,24UL,32UL}){
  len=size;CHECK(f->C_DeriveKey(s,&m,master,attrs,6,&derived)==CKR_OK);
  CHECK(read(root/"symmetric"/"derived.key")==expected.substr(0,len*2));
  CHECK(f->C_DestroyObject(s,derived)==CKR_OK);
 }
 token=CK_FALSE;CHECK(f->C_DeriveKey(s,&m,master,attrs,6,&derived)==CKR_OK);
 CHECK(!std::filesystem::exists(root/"symmetric"/"derived.key"));
 CK_BBOOL actual=CK_TRUE;CK_ATTRIBUTE a{CKA_TOKEN,&actual,sizeof actual};CHECK(f->C_GetAttributeValue(s,derived,&a,1)==CKR_OK);CHECK(actual==CK_FALSE);
 CK_OBJECT_HANDLE same;CHECK(f->C_DeriveKey(s,&m,master,attrs,6,&same)==CKR_OK);
 CK_MECHANISM wrap{CKM_AES_KEY_WRAP_PAD,nullptr,0};CK_ULONG n=0;
 CHECK(f->C_WrapKey(s,&wrap,derived,master,nullptr,&n)==CKR_OK);std::vector<unsigned char> blob(n);
 CHECK(f->C_WrapKey(s,&wrap,derived,master,blob.data(),&n)==CKR_OK);
 std::string restored="restored";CK_ATTRIBUTE unwrap{CKA_LABEL,restored.data(),(CK_ULONG)restored.size()};CK_OBJECT_HANDLE out=0;
 CHECK(f->C_UnwrapKey(s,&wrap,same,blob.data(),n,&unwrap,1,&out)==CKR_OK);
 CHECK(read(root/"symmetric"/"restored.key")==read(root/"symmetric"/"master.key"));
 data[0]^=1;CK_OBJECT_HANDLE different;CHECK(f->C_DeriveKey(s,&m,master,attrs,6,&different)==CKR_OK);
 CHECK(f->C_UnwrapKey(s,&wrap,different,blob.data(),n,&unwrap,1,&out)!=CKR_OK);data[0]^=1;
 CHECK(f->C_DestroyObject(s,derived)==CKR_OK);CHECK(f->C_GetAttributeValue(s,same,&a,1)==CKR_OK);
 input.ulLen=17;CHECK(f->C_DeriveKey(s,&m,master,attrs,6,&out)==CKR_DATA_LEN_RANGE);
 input.ulLen=16;CHECK(f->C_DeriveKey(s,&m,master,attrs,6,&out)==CKR_DATA_LEN_RANGE);input.ulLen=32;
 len=17;CHECK(f->C_DeriveKey(s,&m,master,attrs,6,&out)==CKR_KEY_SIZE_RANGE);len=32;
 CHECK(f->C_DeriveKey(s,&m,999999,attrs,6,&out)==CKR_KEY_HANDLE_INVALID);
 CHECK(f->C_DeriveKey(s,&m,master,nullptr,1,&out)==CKR_ARGUMENTS_BAD);
 m.ulParameterLen=1;CHECK(f->C_DeriveKey(s,&m,master,attrs,6,&out)==CKR_MECHANISM_PARAM_INVALID);m.ulParameterLen=sizeof input;
 attrs[0].ulValueLen=1;CHECK(f->C_DeriveKey(s,&m,master,attrs,6,&out)==CKR_ATTRIBUTE_VALUE_INVALID);attrs[0].ulValueLen=sizeof type;
 CK_SESSION_HANDLE other;CHECK(f->C_OpenSession(1,CKF_SERIAL_SESSION,nullptr,nullptr,&other)==CKR_OK);
 token=CK_TRUE;CHECK(f->C_DeriveKey(other,&m,master,attrs,6,&out)==CKR_SESSION_READ_ONLY);
 CHECK(f->C_DeriveKey(s,&m,master,attrs,6,&out)==CKR_OK);
 CHECK(f->C_CloseSession(s)==CKR_OK);s=other;
 CHECK(f->C_GetAttributeValue(s,same,&a,1)==CKR_OBJECT_HANDLE_INVALID);
 CHECK(f->C_GetAttributeValue(s,out,&a,1)==CKR_OK);CHECK(actual==CK_TRUE);
 CHECK(f->C_Finalize(nullptr)==CKR_OK);CHECK(f->C_Initialize(nullptr)==CKR_OK);
 CHECK(f->C_OpenSession(1,CKF_SERIAL_SESSION|CKF_RW_SESSION,nullptr,nullptr,&s)==CKR_OK);out=find("derived");
 CHECK(read(root/"symmetric"/"derived.key")==expected);
 CHECK(f->C_Finalize(nullptr)==CKR_OK);
 std::cout<<checks<<" derivation checks passed\n";return 0;
 }catch(const std::exception& e){std::cerr<<"FAIL after "<<checks<<": "<<e.what()<<'\n';return 1;}}
