#include "pkcs11.h"
#include <iostream>
#include <stdexcept>
#include <cstddef>
#ifdef _WIN32
#include <windows.h>
static_assert(sizeof(CK_ULONG)==4);
static_assert(sizeof(CK_ATTRIBUTE)==16);
static_assert(offsetof(CK_FUNCTION_LIST,C_Initialize)==2);
static_assert(sizeof(CK_FUNCTION_LIST)==2+68*8);
static_assert(sizeof(CK_FUNCTION_LIST_3_2)==2+104*8);
static_assert(offsetof(CK_FUNCTION_LIST_3_2,C_GetInterfaceList)==sizeof(CK_FUNCTION_LIST));
#else
#include <dlfcn.h>
#endif
static unsigned checks=0;
#define CHECK(x) do {++checks;if(!(x))throw std::runtime_error(#x);} while(false)
int main(int argc,char** argv){
 try{
  CHECK(argc==2);
#ifdef _WIN32
  HMODULE library=LoadLibraryA(argv[1]);CHECK(library);
  auto symbol=[&](const char* name){return GetProcAddress(library,name);};
#else
  void* library=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);CHECK(library);
  auto symbol=[&](const char* name){return dlsym(library,name);};
#endif
  using GetList=CK_RV(CK_CALL*)(CK_FUNCTION_LIST_PTR_PTR);
  GetList getList=reinterpret_cast<GetList>(symbol("C_GetFunctionList"));CHECK(getList);
  CK_FUNCTION_LIST_PTR f=nullptr;CHECK(getList(&f)==CKR_OK);
  CHECK(f->version.major==2&&f->version.minor==40);
  auto list=reinterpret_cast<CK_C_GetInterfaceList>(symbol("C_GetInterfaceList"));
  auto get=reinterpret_cast<CK_C_GetInterface>(symbol("C_GetInterface"));
  CHECK(list&&get);
  CK_ULONG interfaceCount=0;
  CHECK(list(nullptr,nullptr)==CKR_ARGUMENTS_BAD);
  CHECK(list(nullptr,&interfaceCount)==CKR_OK);CHECK(interfaceCount==3);
  CK_INTERFACE available[3];interfaceCount=1;
  CHECK(list(available,&interfaceCount)==CKR_BUFFER_TOO_SMALL);CHECK(interfaceCount==3);
  CHECK(list(available,&interfaceCount)==CKR_OK);
  CK_INTERFACE_PTR selected=nullptr;
  CHECK(get(nullptr,nullptr,&selected,0)==CKR_OK);
  CHECK(selected);
  auto f32=static_cast<CK_FUNCTION_LIST_3_2_PTR>(selected->pFunctionList);
  CHECK(f32->version.major==3&&f32->version.minor==2);
  CHECK(get(nullptr,nullptr,nullptr,0)==CKR_ARGUMENTS_BAD);
  CHECK(get(nullptr,nullptr,&selected,CKF_INTERFACE_FORK_SAFE)==CKR_ARGUMENTS_BAD);
  CK_UTF8CHAR invalidName[]="unknown";
  CHECK(get(invalidName,nullptr,&selected,0)==CKR_ARGUMENTS_BAD);
  CK_VERSION absent{9,9};
  CHECK(get(nullptr,&absent,&selected,0)==CKR_ARGUMENTS_BAD);
  CK_VERSION legacy{2,40};
  CHECK(get(nullptr,&legacy,&selected,0)==CKR_OK);CHECK(selected->pFunctionList==f);
  CK_VERSION v30{3,0};
  CHECK(get(nullptr,&v30,&selected,0)==CKR_OK);
  auto f30=static_cast<CK_FUNCTION_LIST_3_0_PTR>(selected->pFunctionList);
  CHECK(f30->version.major==3&&f30->version.minor==0);
  CHECK(f30->C_Sign==f32->C_Sign&&f32->C_Sign==f->C_Sign);
#define CK_PKCS11_FUNCTION_INFO(name) CHECK(symbol(#name)!=nullptr);CHECK(f32->name!=nullptr);
#include "oasis/pkcs11f.h"
#undef CK_PKCS11_FUNCTION_INFO
  // Check every legacy entry point by exported name and table pointer.
#include "export_checks.inc"
  CK_ULONG count=0;
  CHECK(f->C_GetSlotList(CK_TRUE,nullptr,&count)==CKR_CRYPTOKI_NOT_INITIALIZED);
  CHECK(f->C_CloseSession(999)==CKR_CRYPTOKI_NOT_INITIALIZED);
  CHECK(f->C_Initialize(nullptr)==CKR_OK);
  CK_INFO info{};
  CHECK(f32->C_GetInfo(&info)==CKR_OK);
  CHECK(info.cryptokiVersion.major==3&&info.cryptokiVersion.minor==2);
  CHECK(f->C_Initialize(nullptr)==CKR_CRYPTOKI_ALREADY_INITIALIZED);
  CHECK(f->C_GetSlotList(CK_TRUE,nullptr,&count)==CKR_OK);CHECK(count==1);
  CK_SESSION_HANDLE session;CHECK(f->C_OpenSession(1,CKF_SERIAL_SESSION|CKF_RW_SESSION,nullptr,nullptr,&session)==CKR_OK);
  CHECK(f->C_InitPIN(session,nullptr,0)==CKR_FUNCTION_NOT_SUPPORTED);
  CHECK(f32->C_AsyncGetID(session,nullptr,nullptr)==CKR_FUNCTION_NOT_SUPPORTED);
  CHECK(f32->C_MessageSignInit(session,nullptr,0)==CKR_FUNCTION_NOT_SUPPORTED);
  CHECK(f->C_GetSessionInfo(session,nullptr)==CKR_ARGUMENTS_BAD);
  CHECK(f->C_Finalize(nullptr)==CKR_OK);
  CHECK(f->C_GetMechanismList(1,nullptr,&count)==CKR_CRYPTOKI_NOT_INITIALIZED);
  CHECK(f->C_Finalize(nullptr)==CKR_CRYPTOKI_NOT_INITIALIZED);
#ifdef _WIN32
  CHECK(FreeLibrary(library)!=0);
#else
  CHECK(dlclose(library)==0);
#endif
  std::cout<<checks<<" dynamic loader checks passed\n";return 0;
 }catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<"\n";return 1;}
}
