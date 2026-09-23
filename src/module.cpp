#include "pkcs11.h"
#include "metadata.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <cctype>
#include <limits>
#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace fs=std::filesystem;
template<class T, void(*F)(T*)> using ossl_ptr=std::unique_ptr<T,decltype(F)>;

namespace {
struct Object { CK_OBJECT_HANDLE h{}; CK_OBJECT_CLASS cls{}; CK_KEY_TYPE type{}; std::string label,id,path,param; std::vector<unsigned char> secret,cert; std::shared_ptr<EVP_PKEY> key; CK_SESSION_HANDLE owner{}; };
struct Operation { bool active=false, verify=false; CK_MECHANISM_TYPE mech{}; CK_OBJECT_HANDLE key{}; std::vector<unsigned char> data; CK_RSA_PKCS_PSS_PARAMS pss{}; };
struct Session { CK_SESSION_HANDLE h{}; CK_FLAGS flags{}; bool logged=false, finding=false; std::vector<CK_OBJECT_HANDLE> matches; size_t cursor=0; Operation op; };
struct State { bool initialized=false; fs::path root; CK_OBJECT_HANDLE nextObj=1; CK_SESSION_HANDLE nextSession=1; std::unordered_map<CK_OBJECT_HANDLE,Object> objects; std::unordered_map<CK_SESSION_HANDLE,Session> sessions; std::recursive_mutex mutex; } g;

void blank(CK_CHAR* p,size_t n,const char* s){ std::memset(p,' ',n); std::memcpy(p,s,std::min(n,std::strlen(s))); }
std::string env(const char* n,const char* d){ const char* v=std::getenv(n); return v&&*v?v:d; }
std::string hex(const unsigned char* p,size_t n){ static constexpr char x[]="0123456789ABCDEF"; std::string s; s.reserve(n*2); for(size_t i=0;i<n;i++){s.push_back(x[p[i]>>4]);s.push_back(x[p[i]&15]);}return s; }
std::vector<unsigned char> unhex(std::string s){ s.erase(std::remove_if(s.begin(),s.end(),[](unsigned char c){return std::isspace(c);}),s.end()); if(s.size()%2) return {}; std::vector<unsigned char> r(s.size()/2); for(size_t i=0;i<r.size();i++){try{r[i]=(unsigned char)std::stoul(s.substr(i*2,2),nullptr,16);}catch(...){return {};}}return r; }
std::optional<std::vector<unsigned char>> attr(CK_ATTRIBUTE_PTR a,CK_ULONG n,CK_ATTRIBUTE_TYPE t){
 if(!a)return {};
 for(CK_ULONG i=0;i<n;i++)if(a[i].type==t){
  if(a[i].ulValueLen==0)return std::vector<unsigned char>{};
  if(!a[i].pValue)return {};
  return std::vector<unsigned char>((unsigned char*)a[i].pValue,(unsigned char*)a[i].pValue+a[i].ulValueLen);
 }
 return {};
}
std::string attrstr(CK_ATTRIBUTE_PTR a,CK_ULONG n,CK_ATTRIBUTE_TYPE t,const std::string& d=""){auto v=attr(a,n,t);return v?std::string(v->begin(),v->end()):d;}
std::optional<CK_ULONG> attrulong(CK_ATTRIBUTE_PTR a,CK_ULONG n,CK_ATTRIBUTE_TYPE t){auto v=attr(a,n,t);if(!v||v->size()!=sizeof(CK_ULONG))return {};CK_ULONG z;std::memcpy(&z,v->data(),sizeof z);return z;}
std::string safeLabel(std::string s){ for(auto& c:s) if(!std::isalnum((unsigned char)c)&&c!='-'&&c!='_') c='_'; return s.empty()?"key":s; }
CK_RV ready(){return g.initialized?CKR_OK:CKR_CRYPTOKI_NOT_INITIALIZED;}
Session* session(CK_SESSION_HANDLE h){auto i=g.sessions.find(h);return i==g.sessions.end()?nullptr:&i->second;}
Object* object(CK_OBJECT_HANDLE h){auto i=g.objects.find(h);return i==g.objects.end()?nullptr:&i->second;}
CK_KEY_TYPE typeOf(EVP_PKEY* p){if(EVP_PKEY_is_a(p,"RSA"))return CKK_RSA;if(EVP_PKEY_is_a(p,"EC"))return CKK_EC;if(std::string(EVP_PKEY_get0_type_name(p)).rfind("ML-DSA-",0)==0)return CKK_ML_DSA;if(std::string(EVP_PKEY_get0_type_name(p)).rfind("SLH-DSA-",0)==0)return CKK_SLH_DSA;return ~0UL;}
std::string pkeyName(EVP_PKEY* p){const char* n=EVP_PKEY_get0_type_name(p);return n?n:"";}
std::string stableId(const std::string& filename){
 unsigned char digest[32];unsigned n=0;
 if(EVP_Digest(filename.data(),filename.size(),digest,&n,EVP_sha256(),nullptr)!=1)throw std::runtime_error("ID digest failed");
 return std::string(reinterpret_cast<char*>(digest),n);
}
CK_RV persistMetadata(std::string path){
 try{
  metadata::Records records;
  for(const auto& [handle,o]:g.objects)if(o.path==path)
   records.emplace(static_cast<std::uint32_t>(o.cls),metadata::Attributes{o.label,o.id});
  metadata::create(path,records);return CKR_OK;
 }catch(...){
  // The key file was created by this operation; do not publish a partial object.
  for(auto it=g.objects.begin();it!=g.objects.end();)
   if(it->second.path==path)it=g.objects.erase(it);else ++it;
  std::error_code ec;fs::remove(path,ec);return CKR_DEVICE_ERROR;
 }
}
std::shared_ptr<EVP_PKEY> pubkey(EVP_PKEY* p){unsigned char* der=nullptr;int n=i2d_PUBKEY(p,&der);if(n<=0)return{};const unsigned char* q=der;EVP_PKEY* out=d2i_PUBKEY(nullptr,&q,n);OPENSSL_free(der);return {out,EVP_PKEY_free};}
void addKeyObjects(const std::string& label,const fs::path& path,EVP_PKEY* raw,X509* cert){auto key=std::shared_ptr<EVP_PKEY>(raw,EVP_PKEY_free);auto id=stableId(path.filename().string());Object priv{g.nextObj++,CKO_PRIVATE_KEY,typeOf(raw),label,id,path.string(),pkeyName(raw),{}, {},key};g.objects.emplace(priv.h,priv);auto pub=pubkey(raw);if(pub){Object po{g.nextObj++,CKO_PUBLIC_KEY,priv.type,label,id,path.string(),priv.param,{}, {},pub};g.objects.emplace(po.h,std::move(po));}if(cert){unsigned char* d=nullptr;int n=i2d_X509(cert,&d);Object co{g.nextObj++,CKO_CERTIFICATE,0,label,id,path.string()};if(n>0){co.cert.assign(d,d+n);OPENSSL_free(d);}g.objects.emplace(co.h,std::move(co));X509_free(cert);}}
void load(){g.objects.clear();g.nextObj=1;fs::create_directories(g.root/"asymmetric");fs::create_directories(g.root/"symmetric");std::string pass=env("HSM_SIM_P12_PASSWORD","");for(auto& e:fs::directory_iterator(g.root/"asymmetric")){if(e.path().extension() != ".p12" && e.path().extension() != ".pfx")continue;FILE* f=nullptr;
#ifdef _WIN32
 _wfopen_s(&f,e.path().c_str(),L"rb");
#else
 f=std::fopen(e.path().c_str(),"rb");
#endif
 if(!f)continue;PKCS12* p=d2i_PKCS12_fp(f,nullptr);std::fclose(f);if(!p)continue;EVP_PKEY* k=nullptr;X509* c=nullptr;if(PKCS12_parse(p,pass.c_str(),&k,&c,nullptr)==1&&k)addKeyObjects(e.path().stem().string(),e.path(),k,c);PKCS12_free(p);}for(auto& e:fs::directory_iterator(g.root/"symmetric")){if(e.path().extension()!=".key")continue;std::ifstream in(e.path());std::string s((std::istreambuf_iterator<char>(in)),{});auto b=unhex(s);if(b.empty())continue;Object o{g.nextObj++,CKO_SECRET_KEY,CKK_AES,e.path().stem().string(),stableId(e.path().filename().string()),e.path().string(),{},std::move(b)};g.objects.emplace(o.h,std::move(o));}for(auto& [handle,o]:g.objects){auto records=metadata::read(o.path);auto record=records.find((std::uint32_t)o.cls);if(record!=records.end()){o.label=record->second.label;o.id=record->second.id;}}}
CK_RV saveSecret(Object& o){if(fs::exists(o.path))return CKR_TEMPLATE_INCONSISTENT;std::ofstream f(o.path,std::ios::trunc);if(!f)return CKR_DEVICE_ERROR;f<<hex(o.secret.data(),o.secret.size())<<"\n";return f?CKR_OK:CKR_DEVICE_ERROR;}
CK_RV saveP12(const fs::path& path,EVP_PKEY* key,const std::string& label){if(fs::exists(path))return CKR_TEMPLATE_INCONSISTENT;std::string pass=env("HSM_SIM_P12_PASSWORD","");PKCS12* p=PKCS12_create(pass.c_str(),label.c_str(),key,nullptr,nullptr,0,0,0,0,0);if(!p)return CKR_DEVICE_ERROR;FILE* f=nullptr;
#ifdef _WIN32
 _wfopen_s(&f,path.c_str(),L"wb");
#else
 f=std::fopen(path.c_str(),"wb");
#endif
 int ok=f?i2d_PKCS12_fp(f,p):0;if(f)std::fclose(f);PKCS12_free(p);return ok?CKR_OK:CKR_DEVICE_ERROR;}
bool isPss(CK_MECHANISM_TYPE m){return m==CKM_RSA_PKCS_PSS||m==CKM_SHA256_RSA_PKCS_PSS||m==CKM_SHA384_RSA_PKCS_PSS||m==CKM_SHA512_RSA_PKCS_PSS;}
bool compatible(CK_KEY_TYPE t,CK_MECHANISM_TYPE m){if(t==CKK_RSA)return isPss(m)||m==CKM_RSA_PKCS||m==CKM_SHA256_RSA_PKCS||m==CKM_SHA384_RSA_PKCS||m==CKM_SHA512_RSA_PKCS;if(t==CKK_EC)return m==CKM_ECDSA||m==CKM_ECDSA_SHA256||m==CKM_ECDSA_SHA384||m==CKM_ECDSA_SHA512;if(t==CKK_ML_DSA)return m==CKM_ML_DSA;if(t==CKK_SLH_DSA)return m==CKM_SLH_DSA;return false;}
const EVP_MD* pssHash(CK_MECHANISM_TYPE m){switch(m){case CKM_SHA256:return EVP_sha256();case CKM_SHA384:return EVP_sha384();case CKM_SHA512:return EVP_sha512();default:return nullptr;}}
const EVP_MD* mgfHash(CK_ULONG m){switch(m){case CKG_MGF1_SHA256:return EVP_sha256();case CKG_MGF1_SHA384:return EVP_sha384();case CKG_MGF1_SHA512:return EVP_sha512();default:return nullptr;}}
bool configurePss(EVP_PKEY_CTX* ctx,const CK_RSA_PKCS_PSS_PARAMS& p){
 return EVP_PKEY_CTX_set_rsa_padding(ctx,RSA_PKCS1_PSS_PADDING)>0
  &&EVP_PKEY_CTX_set_signature_md(ctx,pssHash(p.hashAlg))>0
  &&EVP_PKEY_CTX_set_rsa_mgf1_md(ctx,mgfHash(p.mgf))>0
  &&EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx,(int)p.sLen)>0;
}
const EVP_MD* md(CK_MECHANISM_TYPE m){if(m==CKM_SHA256_RSA_PKCS||m==CKM_ECDSA_SHA256)return EVP_sha256();if(m==CKM_SHA384_RSA_PKCS||m==CKM_ECDSA_SHA384)return EVP_sha384();if(m==CKM_SHA512_RSA_PKCS||m==CKM_ECDSA_SHA512)return EVP_sha512();return nullptr;}
// EVP raw operations must not hash CKM_RSA_PKCS or CKM_ECDSA input.
CK_RV crypto(Operation& op,const unsigned char* data,size_t len,unsigned char* sig,size_t* siglen,bool verify) {
 Object* o=object(op.key);
 if(!o||!o->key)return CKR_KEY_HANDLE_INVALID;
 const bool ec=o->type==CKK_EC;
 const size_t width=ec?(EVP_PKEY_get_bits(o->key.get())+7)/8:0;
 const size_t required=ec?2*width:EVP_PKEY_get_size(o->key.get());
 if(!verify) {
  if(!sig){*siglen=required;return CKR_OK;}
  if(*siglen<required){*siglen=required;return CKR_BUFFER_TOO_SMALL;}
 } else if(!sig || (ec&&*siglen!=required)) return CKR_SIGNATURE_LEN_RANGE;
 static const unsigned char empty=0;
 if(!data)data=&empty;
 std::vector<unsigned char> encoded;
 if(verify&&ec) {
  ossl_ptr<ECDSA_SIG,ECDSA_SIG_free> pair(ECDSA_SIG_new(),ECDSA_SIG_free);
  BIGNUM* r=BN_bin2bn(sig,(int)width,nullptr);
  BIGNUM* s=BN_bin2bn(sig+width,(int)width,nullptr);
  if(!pair||!r||!s){BN_free(r);BN_free(s);return CKR_HOST_MEMORY;}
  if(!ECDSA_SIG_set0(pair.get(),r,s)){BN_free(r);BN_free(s);return CKR_DEVICE_ERROR;}
  int n=i2d_ECDSA_SIG(pair.get(),nullptr);
  if(n<=0)return CKR_DEVICE_ERROR;
  encoded.resize(n);auto p=encoded.data();i2d_ECDSA_SIG(pair.get(),&p);
 }
 std::vector<unsigned char> result(EVP_PKEY_get_size(o->key.get()));
 size_t resultLen=result.size();
 const unsigned char* inputSig=ec?encoded.data():sig;
 size_t inputSigLen=ec?encoded.size():*siglen;
 const bool raw=op.mech==CKM_RSA_PKCS||op.mech==CKM_ECDSA||op.mech==CKM_RSA_PKCS_PSS;
 int ok=0;
 if(raw) {
  if(op.mech==CKM_RSA_PKCS&&len>required-11)return CKR_DATA_LEN_RANGE;
  ossl_ptr<EVP_PKEY_CTX,EVP_PKEY_CTX_free> ctx(EVP_PKEY_CTX_new_from_pkey(nullptr,o->key.get(),nullptr),EVP_PKEY_CTX_free);
  if(!ctx)return CKR_HOST_MEMORY;
  if((verify?EVP_PKEY_verify_init(ctx.get()):EVP_PKEY_sign_init(ctx.get()))<=0)return CKR_DEVICE_ERROR;
  if(op.mech==CKM_RSA_PKCS_PSS){
   if(len!=(size_t)EVP_MD_get_size(pssHash(op.pss.hashAlg)))return CKR_DATA_LEN_RANGE;
   if(!configurePss(ctx.get(),op.pss))return CKR_MECHANISM_PARAM_INVALID;
  }else if(!ec&&EVP_PKEY_CTX_set_rsa_padding(ctx.get(),RSA_PKCS1_PADDING)<=0)return CKR_DEVICE_ERROR;
  ok=verify?EVP_PKEY_verify(ctx.get(),inputSig,inputSigLen,data,len):
            EVP_PKEY_sign(ctx.get(),result.data(),&resultLen,data,len);
 } else {
  ossl_ptr<EVP_MD_CTX,EVP_MD_CTX_free> ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free);
  if(!ctx)return CKR_HOST_MEMORY;
  EVP_PKEY_CTX* pkctx=nullptr;
  const EVP_MD* digest=isPss(op.mech)?pssHash(op.pss.hashAlg):md(op.mech);
  if((verify?EVP_DigestVerifyInit(ctx.get(),&pkctx,digest,nullptr,o->key.get()):
             EVP_DigestSignInit(ctx.get(),&pkctx,digest,nullptr,o->key.get()))<=0)return CKR_MECHANISM_INVALID;
  if(isPss(op.mech)&&!configurePss(pkctx,op.pss))return CKR_MECHANISM_PARAM_INVALID;
  ok=verify?EVP_DigestVerify(ctx.get(),inputSig,inputSigLen,data,len):
            EVP_DigestSign(ctx.get(),result.data(),&resultLen,data,len);
 }
 if(verify)return ok==1?CKR_OK:CKR_SIGNATURE_INVALID;
 if(ok<=0)return CKR_DEVICE_ERROR;
 if(ec) {
  const unsigned char* p=result.data();
  ossl_ptr<ECDSA_SIG,ECDSA_SIG_free> pair(d2i_ECDSA_SIG(nullptr,&p,(long)resultLen),ECDSA_SIG_free);
  if(!pair)return CKR_DEVICE_ERROR;
  const BIGNUM *r=nullptr,*s=nullptr;ECDSA_SIG_get0(pair.get(),&r,&s);
  if(BN_bn2binpad(r,sig,(int)width)!=(int)width||BN_bn2binpad(s,sig+width,(int)width)!=(int)width)return CKR_DEVICE_ERROR;
  *siglen=required;
 } else {std::memcpy(sig,result.data(),resultLen);*siglen=resultLen;}
 return CKR_OK;
}
CK_RV unsupported(){return CKR_FUNCTION_NOT_SUPPORTED;}
}

static CK_RV Initialize(CK_VOID_PTR p){std::scoped_lock l(g.mutex);if(g.initialized)return CKR_CRYPTOKI_ALREADY_INITIALIZED;if(p&&((CK_C_INITIALIZE_ARGS_PTR)p)->pReserved)return CKR_ARGUMENTS_BAD;g.root=fs::u8path(env("HSM_SIM_DATA_DIR","data"));try{load();}catch(...){return CKR_DEVICE_ERROR;}g.initialized=true;return CKR_OK;}
static CK_RV Finalize(CK_VOID_PTR p){std::scoped_lock l(g.mutex);if(!g.initialized)return CKR_CRYPTOKI_NOT_INITIALIZED;if(p)return CKR_ARGUMENTS_BAD;g.sessions.clear();g.objects.clear();g.initialized=false;return CKR_OK;}
static CK_RV CK_CALL GetInfo(CK_INFO_PTR p){if(!p)return CKR_ARGUMENTS_BAD;std::memset(p,0,sizeof(*p));p->cryptokiVersion={3,2};blank(p->manufacturerID,32,"OpenAI");blank(p->libraryDescription,32,"HSM Simulator");p->libraryVersion={0,6};return ready();}
static CK_RV CK_CALL GetSlotList(CK_BBOOL,CK_SLOT_ID_PTR p,CK_ULONG_PTR n){if(!n)return CKR_ARGUMENTS_BAD;if(!p){*n=1;return CKR_OK;}if(*n<1){*n=1;return CKR_BUFFER_TOO_SMALL;}p[0]=1;*n=1;return ready();}
static CK_RV CK_CALL GetSlotInfo(CK_SLOT_ID s,CK_SLOT_INFO_PTR p){if(s!=1)return CKR_SLOT_ID_INVALID;if(!p)return CKR_ARGUMENTS_BAD;std::memset(p,0,sizeof(*p));blank(p->slotDescription,64,"File-backed virtual HSM slot");blank(p->manufacturerID,32,"OpenAI");p->flags=CKF_TOKEN_PRESENT;p->hardwareVersion={1,0};p->firmwareVersion={0,1};return ready();}
static CK_RV CK_CALL GetTokenInfo(CK_SLOT_ID s,CK_TOKEN_INFO_PTR p){if(s!=1)return CKR_SLOT_ID_INVALID;if(!p)return CKR_ARGUMENTS_BAD;std::memset(p,0,sizeof(*p));blank(p->label,32,"HSM Simulator");blank(p->manufacturerID,32,"OpenAI");blank(p->model,16,"FILE-HSM");blank(p->serialNumber,16,"0000000000000001");p->flags=CKF_RNG|CKF_LOGIN_REQUIRED|CKF_USER_PIN_INITIALIZED;p->ulMaxSessionCount=p->ulMaxRwSessionCount=CK_UNAVAILABLE_INFORMATION;p->ulSessionCount=p->ulRwSessionCount=(CK_ULONG)g.sessions.size();p->ulMinPinLen=0;p->ulMaxPinLen=256;p->hardwareVersion={1,0};p->firmwareVersion={0,1};return ready();}
static const std::array<CK_MECHANISM_TYPE,22> mechs={CKM_AES_ECB_ENCRYPT_DATA,CKM_RSA_PKCS_KEY_PAIR_GEN,CKM_RSA_PKCS,CKM_SHA256_RSA_PKCS,CKM_SHA384_RSA_PKCS,CKM_SHA512_RSA_PKCS,CKM_EC_KEY_PAIR_GEN,CKM_ECDSA,CKM_ECDSA_SHA256,CKM_ECDSA_SHA384,CKM_ECDSA_SHA512,CKM_AES_KEY_GEN,CKM_AES_KEY_WRAP,CKM_AES_KEY_WRAP_PAD,CKM_ML_DSA_KEY_PAIR_GEN,CKM_ML_DSA,CKM_SLH_DSA_KEY_PAIR_GEN,CKM_SLH_DSA,CKM_RSA_PKCS_PSS,CKM_SHA256_RSA_PKCS_PSS,CKM_SHA384_RSA_PKCS_PSS,CKM_SHA512_RSA_PKCS_PSS};
static CK_RV CK_CALL GetMechanismList(CK_SLOT_ID s,CK_MECHANISM_TYPE_PTR p,CK_ULONG_PTR n){if(s!=1)return CKR_SLOT_ID_INVALID;if(!n)return CKR_ARGUMENTS_BAD;if(!p){*n=mechs.size();return CKR_OK;}if(*n<mechs.size()){*n=mechs.size();return CKR_BUFFER_TOO_SMALL;}std::copy(mechs.begin(),mechs.end(),p);*n=mechs.size();return CKR_OK;}
static CK_RV CK_CALL GetMechanismInfo(CK_SLOT_ID s,CK_MECHANISM_TYPE m,CK_MECHANISM_INFO_PTR p){if(s!=1)return CKR_SLOT_ID_INVALID;if(!p)return CKR_ARGUMENTS_BAD;if(std::find(mechs.begin(),mechs.end(),m)==mechs.end())return CKR_MECHANISM_INVALID;p->ulMinKeySize=0;p->ulMaxKeySize=0;p->flags=0;if(m==CKM_AES_ECB_ENCRYPT_DATA){p->ulMinKeySize=16;p->ulMaxKeySize=32;p->flags=CKF_DERIVE;}else if(m==CKM_AES_KEY_GEN)p->flags=CKF_GENERATE;else if(m==CKM_RSA_PKCS_KEY_PAIR_GEN||m==CKM_EC_KEY_PAIR_GEN||m==CKM_ML_DSA_KEY_PAIR_GEN||m==CKM_SLH_DSA_KEY_PAIR_GEN)p->flags=CKF_GENERATE_KEY_PAIR;else if(m==CKM_AES_KEY_WRAP||m==CKM_AES_KEY_WRAP_PAD)p->flags=CKF_WRAP|CKF_UNWRAP;else p->flags=CKF_SIGN|CKF_VERIFY;return CKR_OK;}
static CK_RV CK_CALL OpenSession(CK_SLOT_ID s,CK_FLAGS f,CK_VOID_PTR,CK_NOTIFY,CK_SESSION_HANDLE_PTR h){std::scoped_lock l(g.mutex);if(ready())return ready();if(s!=1)return CKR_SLOT_ID_INVALID;if(!h||!(f&CKF_SERIAL_SESSION))return CKR_ARGUMENTS_BAD;Session x{g.nextSession++,f};*h=x.h;g.sessions.emplace(x.h,std::move(x));return CKR_OK;}
static CK_RV CK_CALL CloseSession(CK_SESSION_HANDLE h){std::scoped_lock l(g.mutex);if(!g.sessions.erase(h))return CKR_SESSION_HANDLE_INVALID;for(auto it=g.objects.begin();it!=g.objects.end();)if(it->second.owner==h)it=g.objects.erase(it);else ++it;return CKR_OK;}
static CK_RV CK_CALL CloseAllSessions(CK_SLOT_ID s){if(s!=1)return CKR_SLOT_ID_INVALID;std::scoped_lock l(g.mutex);g.sessions.clear();for(auto it=g.objects.begin();it!=g.objects.end();)if(it->second.owner)it=g.objects.erase(it);else ++it;return CKR_OK;}
static CK_RV CK_CALL GetSessionInfo(CK_SESSION_HANDLE h,CK_SESSION_INFO_PTR p){std::scoped_lock l(g.mutex);auto* s=session(h);if(!s)return CKR_SESSION_HANDLE_INVALID;if(!p)return CKR_ARGUMENTS_BAD;p->slotID=1;p->flags=s->flags;p->state=s->logged?((s->flags&CKF_RW_SESSION)?CKS_RW_USER_FUNCTIONS:CKS_RO_USER_FUNCTIONS):((s->flags&CKF_RW_SESSION)?CKS_RW_PUBLIC_SESSION:CKS_RO_PUBLIC_SESSION);p->ulDeviceError=0;return CKR_OK;}
static CK_RV CK_CALL Login(CK_SESSION_HANDLE h,CK_USER_TYPE u,CK_CHAR_PTR pin,CK_ULONG n){std::scoped_lock l(g.mutex);auto*s=session(h);if(!s)return CKR_SESSION_HANDLE_INVALID;if(u!=CKU_USER&&u!=CKU_SO)return CKR_USER_TYPE_INVALID;if(s->logged)return CKR_USER_ALREADY_LOGGED_IN;std::string expected=env("HSM_SIM_PIN","");if(!expected.empty()&&(!pin||std::string(pin,pin+n)!=expected))return CKR_PIN_INCORRECT;s->logged=true;return CKR_OK;}
static CK_RV CK_CALL Logout(CK_SESSION_HANDLE h){std::scoped_lock l(g.mutex);auto*s=session(h);if(!s)return CKR_SESSION_HANDLE_INVALID;if(!s->logged)return CKR_USER_NOT_LOGGED_IN;s->logged=false;return CKR_OK;}
static CK_RV CK_CALL DestroyObject(CK_SESSION_HANDLE h,CK_OBJECT_HANDLE oh){
 std::scoped_lock l(g.mutex);if(!session(h))return CKR_SESSION_HANDLE_INVALID;
 auto*o=object(oh);if(!o)return CKR_OBJECT_HANDLE_INVALID;
 if(o->owner){g.objects.erase(oh);return CKR_OK;}
 auto path=o->path;std::error_code ec;fs::remove(path,ec);if(ec)return CKR_DEVICE_ERROR;
 fs::remove(metadata::path(path),ec);
 for(auto i=g.objects.begin();i!=g.objects.end();)if(i->second.path==path)i=g.objects.erase(i);else++i;
 return ec?CKR_DEVICE_ERROR:CKR_OK;
}
static CK_RV put(CK_ATTRIBUTE& a,const void* p,size_t n){if(!a.pValue){a.ulValueLen=n;return CKR_OK;}if(a.ulValueLen<n){a.ulValueLen=n;return CKR_BUFFER_TOO_SMALL;}std::memcpy(a.pValue,p,n);a.ulValueLen=n;return CKR_OK;}
static CK_ULONG parameterSet(const Object& o){if(o.type==CKK_ML_DSA){if(o.param.find("44")!=std::string::npos)return CKP_ML_DSA_44;if(o.param.find("87")!=std::string::npos)return CKP_ML_DSA_87;return CKP_ML_DSA_65;}if(o.type==CKK_SLH_DSA){static const char* names[]={"SHA2-128s","SHAKE-128s","SHA2-128f","SHAKE-128f","SHA2-192s","SHAKE-192s","SHA2-192f","SHAKE-192f","SHA2-256s","SHAKE-256s","SHA2-256f","SHAKE-256f"};for(CK_ULONG i=0;i<12;i++)if(o.param.find(names[i])!=std::string::npos)return i+1;}return 0;}
static CK_RV readAttributes(Object* o,CK_ATTRIBUTE_PTR a,CK_ULONG n){if(!a&&n)return CKR_ARGUMENTS_BAD;CK_RV rv=CKR_OK;for(CK_ULONG i=0;i<n;i++){CK_RV x=CKR_OK;switch(a[i].type){case CKA_DERIVE:case CKA_TOKEN:case CKA_PRIVATE:case CKA_SIGN:case CKA_VERIFY:case CKA_WRAP:case CKA_UNWRAP:case CKA_EXTRACTABLE:case CKA_SENSITIVE:{
 CK_BBOOL value=CK_TRUE;
 if(a[i].type==CKA_TOKEN)value=o->owner?CK_FALSE:CK_TRUE;
 if(a[i].type==CKA_DERIVE)value=o->type==CKK_AES&&o->cls==CKO_SECRET_KEY;
 if(a[i].type==CKA_SENSITIVE)value=CK_FALSE;
 if(a[i].type==CKA_PRIVATE||a[i].type==CKA_SIGN)value=o->cls==CKO_PRIVATE_KEY;
 if(a[i].type==CKA_VERIFY)value=o->cls==CKO_PUBLIC_KEY;
 if(a[i].type==CKA_WRAP||a[i].type==CKA_UNWRAP)value=o->type==CKK_AES&&o->cls==CKO_SECRET_KEY;
 x=put(a[i],&value,sizeof value);break;}
 case CKA_VALUE_LEN:{CK_ULONG value=o->secret.size();x=put(a[i],&value,sizeof value);break;}
 case CKA_MODULUS_BITS:{if(!o->key||o->type!=CKK_RSA){x=CKR_ATTRIBUTE_TYPE_INVALID;a[i].ulValueLen=CK_UNAVAILABLE_INFORMATION;break;}CK_ULONG value=EVP_PKEY_get_bits(o->key.get());x=put(a[i],&value,sizeof value);break;}
 case CKA_MODULUS:case CKA_PUBLIC_EXPONENT:{
 BIGNUM* bn=nullptr;
 if(!o->key||o->type!=CKK_RSA||EVP_PKEY_get_bn_param(o->key.get(),a[i].type==CKA_MODULUS?OSSL_PKEY_PARAM_RSA_N:OSSL_PKEY_PARAM_RSA_E,&bn)!=1){x=CKR_ATTRIBUTE_TYPE_INVALID;a[i].ulValueLen=CK_UNAVAILABLE_INFORMATION;break;}
 ossl_ptr<BIGNUM,BN_free> number(bn,BN_free);std::vector<unsigned char> bytes(BN_num_bytes(bn));BN_bn2bin(bn,bytes.data());x=put(a[i],bytes.data(),bytes.size());break;}
 case CKA_EC_PARAMS:case CKA_EC_POINT:{
 if(!o->key||o->type!=CKK_EC){x=CKR_ATTRIBUTE_TYPE_INVALID;a[i].ulValueLen=CK_UNAVAILABLE_INFORMATION;break;}
 std::vector<unsigned char> bytes;
 if(a[i].type==CKA_EC_PARAMS){
  char group[128];size_t size=0;
  if(EVP_PKEY_get_utf8_string_param(o->key.get(),OSSL_PKEY_PARAM_GROUP_NAME,group,sizeof group,&size)!=1){x=CKR_DEVICE_ERROR;break;}
  const ASN1_OBJECT* oid=OBJ_nid2obj(OBJ_txt2nid(group));
  int n=oid?i2d_ASN1_OBJECT(oid,nullptr):0;if(n<=0){x=CKR_DEVICE_ERROR;break;}bytes.resize(n);auto p=bytes.data();i2d_ASN1_OBJECT(oid,&p);
 }else{
  size_t size=0;if(EVP_PKEY_get_octet_string_param(o->key.get(),OSSL_PKEY_PARAM_PUB_KEY,nullptr,0,&size)!=1){x=CKR_DEVICE_ERROR;break;}
  std::vector<unsigned char> raw(size);if(EVP_PKEY_get_octet_string_param(o->key.get(),OSSL_PKEY_PARAM_PUB_KEY,raw.data(),raw.size(),&size)!=1){x=CKR_DEVICE_ERROR;break;}
  ossl_ptr<ASN1_OCTET_STRING,ASN1_OCTET_STRING_free> oct(ASN1_OCTET_STRING_new(),ASN1_OCTET_STRING_free);
  if(!oct||ASN1_OCTET_STRING_set(oct.get(),raw.data(),(int)size)!=1){x=CKR_DEVICE_ERROR;break;}
  int n=i2d_ASN1_OCTET_STRING(oct.get(),nullptr);bytes.resize(n);auto p=bytes.data();i2d_ASN1_OCTET_STRING(oct.get(),&p);
 }
 x=put(a[i],bytes.data(),bytes.size());break;}
 case CKA_CLASS:x=put(a[i],&o->cls,sizeof o->cls);break;case CKA_KEY_TYPE:x=put(a[i],&o->type,sizeof o->type);break;case CKA_LABEL:x=put(a[i],o->label.data(),o->label.size());break;case CKA_ID:x=put(a[i],o->id.data(),o->id.size());break;case CKA_PARAMETER_SET:{auto ps=parameterSet(*o);if(!ps){x=CKR_ATTRIBUTE_TYPE_INVALID;a[i].ulValueLen=CK_UNAVAILABLE_INFORMATION;}else x=put(a[i],&ps,sizeof ps);break;}case CKA_VALUE:if(o->cls==CKO_CERTIFICATE)x=put(a[i],o->cert.data(),o->cert.size());else{x=CKR_ATTRIBUTE_TYPE_INVALID;a[i].ulValueLen=CK_UNAVAILABLE_INFORMATION;}break;default:x=CKR_ATTRIBUTE_TYPE_INVALID;a[i].ulValueLen=CK_UNAVAILABLE_INFORMATION;}if(x!=CKR_OK)rv=x;}return rv;}
static CK_RV CK_CALL GetAttributeValue(CK_SESSION_HANDLE h,CK_OBJECT_HANDLE oh,CK_ATTRIBUTE_PTR a,CK_ULONG n){
 std::scoped_lock l(g.mutex);
 if(!session(h))return CKR_SESSION_HANDLE_INVALID;
 auto* o=object(oh);if(!o)return CKR_OBJECT_HANDLE_INVALID;
 return readAttributes(o,a,n);
}
static CK_RV CK_CALL FindInit(CK_SESSION_HANDLE h,CK_ATTRIBUTE_PTR a,CK_ULONG n){
 std::scoped_lock l(g.mutex);auto*s=session(h);
 if(!s)return CKR_SESSION_HANDLE_INVALID;
 if(!a&&n)return CKR_ARGUMENTS_BAD;
 for(CK_ULONG i=0;i<n;i++)if(!a[i].pValue&&a[i].ulValueLen)return CKR_ARGUMENTS_BAD;
 if(s->finding)return CKR_OPERATION_ACTIVE;
 s->matches.clear();
 for(auto& [id,o]:g.objects){
  bool matches=true;
  for(CK_ULONG i=0;i<n&&matches;i++){
   CK_ATTRIBUTE probe{a[i].type,nullptr,0};
   if(readAttributes(&o,&probe,1)!=CKR_OK||probe.ulValueLen!=a[i].ulValueLen){matches=false;break;}
   std::vector<unsigned char> value(probe.ulValueLen);probe.pValue=value.data();
   if(readAttributes(&o,&probe,1)!=CKR_OK){matches=false;break;}
   if(probe.ulValueLen&&std::memcmp(value.data(),a[i].pValue,probe.ulValueLen)!=0)matches=false;
  }
  if(matches)s->matches.push_back(id);
 }
 std::sort(s->matches.begin(),s->matches.end());s->cursor=0;s->finding=true;return CKR_OK;
}
static CK_RV CK_CALL Find(CK_SESSION_HANDLE h,CK_OBJECT_HANDLE_PTR out,CK_ULONG max,CK_ULONG_PTR n){std::scoped_lock l(g.mutex);auto*s=session(h);if(!s)return CKR_SESSION_HANDLE_INVALID;if(!s->finding)return CKR_OPERATION_NOT_INITIALIZED;if(!n||(!out&&max))return CKR_ARGUMENTS_BAD;*n=0;while(*n<max&&s->cursor<s->matches.size())out[(*n)++]=s->matches[s->cursor++];return CKR_OK;}
static CK_RV CK_CALL FindFinal(CK_SESSION_HANDLE h){std::scoped_lock l(g.mutex);auto*s=session(h);if(!s)return CKR_SESSION_HANDLE_INVALID;if(!s->finding)return CKR_OPERATION_NOT_INITIALIZED;s->finding=false;s->matches.clear();return CKR_OK;}
static CK_RV initOp(CK_SESSION_HANDLE h,CK_MECHANISM_PTR m,CK_OBJECT_HANDLE k,bool verify){
 auto*s=session(h);if(!s)return CKR_SESSION_HANDLE_INVALID;
 if(!m)return CKR_ARGUMENTS_BAD;
 if(s->op.active)return CKR_OPERATION_ACTIVE;
 auto*o=object(k);if(!o||!o->key)return CKR_KEY_HANDLE_INVALID;
 if(std::find(mechs.begin(),mechs.end(),m->mechanism)==mechs.end())return CKR_MECHANISM_INVALID;
 if(!verify&&o->cls!=CKO_PRIVATE_KEY)return CKR_KEY_TYPE_INCONSISTENT;
 if(!compatible(o->type,m->mechanism))return CKR_KEY_TYPE_INCONSISTENT;
 CK_RSA_PKCS_PSS_PARAMS params{};
 if(isPss(m->mechanism)){
  if(!m->pParameter||m->ulParameterLen!=sizeof params)return CKR_MECHANISM_PARAM_INVALID;
  std::memcpy(&params,m->pParameter,sizeof params);
  const EVP_MD* hash=pssHash(params.hashAlg);
  if(!hash||!mgfHash(params.mgf))return CKR_MECHANISM_PARAM_INVALID;
  CK_MECHANISM_TYPE expected=m->mechanism==CKM_SHA256_RSA_PKCS_PSS?CKM_SHA256:
   m->mechanism==CKM_SHA384_RSA_PKCS_PSS?CKM_SHA384:
   m->mechanism==CKM_SHA512_RSA_PKCS_PSS?CKM_SHA512:params.hashAlg;
  if(expected!=params.hashAlg)return CKR_MECHANISM_PARAM_INVALID;
  // emLen = ceil((modBits - 1) / 8), per EMSA-PSS.
  const int maxSalt=(EVP_PKEY_get_bits(o->key.get())+6)/8-EVP_MD_get_size(hash)-2;
  if(maxSalt<0||params.sLen>(CK_ULONG)maxSalt)return CKR_MECHANISM_PARAM_INVALID;
 }else if(m->pParameter||m->ulParameterLen)return CKR_MECHANISM_PARAM_INVALID;
 s->op={true,verify,m->mechanism,k,{},params};return CKR_OK;
}
static CK_RV CK_CALL SignInit(CK_SESSION_HANDLE h,CK_MECHANISM_PTR m,CK_OBJECT_HANDLE k){std::scoped_lock l(g.mutex);return initOp(h,m,k,false);}
static CK_RV CK_CALL Sign(CK_SESSION_HANDLE h,CK_BYTE_PTR d,CK_ULONG n,CK_BYTE_PTR sig,CK_ULONG_PTR sn){std::scoped_lock l(g.mutex);auto*s=session(h);if(!s)return CKR_SESSION_HANDLE_INVALID;if(!s->op.active||s->op.verify)return CKR_OPERATION_NOT_INITIALIZED;if(!sn||(!d&&n))return CKR_ARGUMENTS_BAD;size_t z=*sn;auto rv=crypto(s->op,d,n,sig,&z,false);*sn=(CK_ULONG)z;if(sig&&rv!=CKR_BUFFER_TOO_SMALL)s->op.active=false;return rv;}
static CK_RV CK_CALL SignUpdate(CK_SESSION_HANDLE h,CK_BYTE_PTR d,CK_ULONG n){std::scoped_lock l(g.mutex);auto*s=session(h);if(!s)return CKR_SESSION_HANDLE_INVALID;if(!s->op.active||s->op.verify)return CKR_OPERATION_NOT_INITIALIZED;if(!d&&n)return CKR_ARGUMENTS_BAD;if(s->op.mech==CKM_RSA_PKCS||s->op.mech==CKM_ECDSA||s->op.mech==CKM_RSA_PKCS_PSS){s->op.active=false;return CKR_MECHANISM_INVALID;}
 if(n>64*1024*1024||s->op.data.size()>64*1024*1024-n){s->op.active=false;return CKR_DATA_LEN_RANGE;}
 if(n)s->op.data.insert(s->op.data.end(),d,d+n);return CKR_OK;}
static CK_RV CK_CALL SignFinal(CK_SESSION_HANDLE h,CK_BYTE_PTR sig,CK_ULONG_PTR sn){std::scoped_lock l(g.mutex);auto*s=session(h);if(!s)return CKR_SESSION_HANDLE_INVALID;if(!s->op.active||s->op.verify)return CKR_OPERATION_NOT_INITIALIZED;if(!sn)return CKR_ARGUMENTS_BAD;size_t z=*sn;auto rv=crypto(s->op,s->op.data.data(),s->op.data.size(),sig,&z,false);*sn=(CK_ULONG)z;if(sig&&rv!=CKR_BUFFER_TOO_SMALL)s->op.active=false;return rv;}
static CK_RV CK_CALL VerifyInit(CK_SESSION_HANDLE h,CK_MECHANISM_PTR m,CK_OBJECT_HANDLE k){std::scoped_lock l(g.mutex);return initOp(h,m,k,true);}
static CK_RV CK_CALL Verify(CK_SESSION_HANDLE h,CK_BYTE_PTR d,CK_ULONG n,CK_BYTE_PTR sig,CK_ULONG sn){std::scoped_lock l(g.mutex);auto*s=session(h);if(!s)return CKR_SESSION_HANDLE_INVALID;if(!s->op.active||!s->op.verify)return CKR_OPERATION_NOT_INITIALIZED;if((!d&&n)||(!sig&&sn))return CKR_ARGUMENTS_BAD;size_t z=sn;auto rv=crypto(s->op,d,n,sig,&z,true);s->op.active=false;return rv;}
static CK_RV CK_CALL VerifyUpdate(CK_SESSION_HANDLE h,CK_BYTE_PTR d,CK_ULONG n){std::scoped_lock l(g.mutex);auto*s=session(h);if(!s)return CKR_SESSION_HANDLE_INVALID;if(!s->op.active||!s->op.verify)return CKR_OPERATION_NOT_INITIALIZED;if(!d&&n)return CKR_ARGUMENTS_BAD;if(s->op.mech==CKM_RSA_PKCS||s->op.mech==CKM_ECDSA||s->op.mech==CKM_RSA_PKCS_PSS){s->op.active=false;return CKR_MECHANISM_INVALID;}
 if(n>64*1024*1024||s->op.data.size()>64*1024*1024-n){s->op.active=false;return CKR_DATA_LEN_RANGE;}
 if(n)s->op.data.insert(s->op.data.end(),d,d+n);return CKR_OK;}
static CK_RV CK_CALL VerifyFinal(CK_SESSION_HANDLE h,CK_BYTE_PTR sig,CK_ULONG sn){std::scoped_lock l(g.mutex);auto*s=session(h);if(!s)return CKR_SESSION_HANDLE_INVALID;if(!s->op.active||!s->op.verify)return CKR_OPERATION_NOT_INITIALIZED;if(!sig&&sn)return CKR_ARGUMENTS_BAD;size_t z=sn;auto rv=crypto(s->op,s->op.data.data(),s->op.data.size(),sig,&z,true);s->op.active=false;return rv;}
static CK_RV CK_CALL GenerateKey(CK_SESSION_HANDLE h,CK_MECHANISM_PTR m,CK_ATTRIBUTE_PTR a,CK_ULONG n,CK_OBJECT_HANDLE_PTR out){std::scoped_lock l(g.mutex);if(!session(h))return CKR_SESSION_HANDLE_INVALID;if(!m||!out)return CKR_ARGUMENTS_BAD;if(m->mechanism!=CKM_AES_KEY_GEN)return CKR_MECHANISM_INVALID;CK_ULONG bytes=attrulong(a,n,CKA_VALUE_LEN).value_or(32);if(bytes!=16&&bytes!=24&&bytes!=32)return CKR_KEY_SIZE_RANGE;Object o;o.h=g.nextObj++;o.cls=CKO_SECRET_KEY;o.type=CKK_AES;o.label=attrstr(a,n,CKA_LABEL,"aes-key");o.id=attrstr(a,n,CKA_ID,std::to_string(o.h));o.path=(g.root/"symmetric"/(safeLabel(o.label)+".key")).string();o.secret.resize(bytes);if(RAND_bytes(o.secret.data(),(int)bytes)!=1)return CKR_DEVICE_ERROR;auto rv=saveSecret(o);if(rv)return rv;auto handle=o.h;g.objects.emplace(handle,std::move(o));rv=persistMetadata(g.objects.at(handle).path);if(rv)return rv;*out=handle;return CKR_OK;}
static std::string algorithm(CK_MECHANISM_TYPE m,CK_ATTRIBUTE_PTR a,CK_ULONG n){if(m==CKM_RSA_PKCS_KEY_PAIR_GEN)return "RSA";if(m==CKM_EC_KEY_PAIR_GEN)return "EC";if(m==CKM_ML_DSA_KEY_PAIR_GEN){switch(attrulong(a,n,CKA_PARAMETER_SET).value_or(CKP_ML_DSA_65)){case CKP_ML_DSA_44:return "ML-DSA-44";case CKP_ML_DSA_65:return "ML-DSA-65";case CKP_ML_DSA_87:return "ML-DSA-87";default:return {};}}if(m==CKM_SLH_DSA_KEY_PAIR_GEN){static const char* names[]={"SLH-DSA-SHA2-128s","SLH-DSA-SHAKE-128s","SLH-DSA-SHA2-128f","SLH-DSA-SHAKE-128f","SLH-DSA-SHA2-192s","SLH-DSA-SHAKE-192s","SLH-DSA-SHA2-192f","SLH-DSA-SHAKE-192f","SLH-DSA-SHA2-256s","SLH-DSA-SHAKE-256s","SLH-DSA-SHA2-256f","SLH-DSA-SHAKE-256f"};auto ps=attrulong(a,n,CKA_PARAMETER_SET).value_or(CKP_SLH_DSA_SHA2_128S);return ps>=1&&ps<=12?names[ps-1]:"";}return {};}
static CK_RV CK_CALL GenerateKeyPair(CK_SESSION_HANDLE h,CK_MECHANISM_PTR m,CK_ATTRIBUTE_PTR pub,CK_ULONG pn,CK_ATTRIBUTE_PTR priv,CK_ULONG qn,CK_OBJECT_HANDLE_PTR ph,CK_OBJECT_HANDLE_PTR qh){std::scoped_lock l(g.mutex);if(!session(h))return CKR_SESSION_HANDLE_INVALID;if(!m||!ph||!qh||(!pub&&pn)||(!priv&&qn))return CKR_ARGUMENTS_BAD;std::string alg=algorithm(m->mechanism,pub,pn);if(alg.empty())return CKR_MECHANISM_INVALID;ossl_ptr<EVP_PKEY_CTX,EVP_PKEY_CTX_free> c(EVP_PKEY_CTX_new_from_name(nullptr,alg.c_str(),nullptr),EVP_PKEY_CTX_free);if(!c||EVP_PKEY_keygen_init(c.get())<=0)return CKR_MECHANISM_INVALID;if(alg=="RSA"){auto bits=attrulong(pub,pn,CKA_MODULUS_BITS).value_or(3072);if(EVP_PKEY_CTX_set_rsa_keygen_bits(c.get(),(int)bits)<=0)return CKR_ATTRIBUTE_VALUE_INVALID;}if(alg=="EC"){
 auto params=attr(pub,pn,CKA_EC_PARAMS);if(!params)return CKR_TEMPLATE_INCOMPLETE;
 const unsigned char* ptr=params->data();
 ossl_ptr<ASN1_OBJECT,ASN1_OBJECT_free> oid(d2i_ASN1_OBJECT(nullptr,&ptr,(long)params->size()),ASN1_OBJECT_free);
 if(!oid||ptr!=params->data()+params->size())return CKR_ATTRIBUTE_VALUE_INVALID;
 const char* group=OBJ_nid2sn(OBJ_obj2nid(oid.get()));
 if(!group||EVP_PKEY_CTX_set_group_name(c.get(),group)<=0)return CKR_ATTRIBUTE_VALUE_INVALID;
}EVP_PKEY* raw=nullptr;if(EVP_PKEY_generate(c.get(),&raw)<=0)return CKR_DEVICE_ERROR;std::string label=attrstr(priv,qn,CKA_LABEL,attrstr(pub,pn,CKA_LABEL,"generated-key"));fs::path path=g.root/"asymmetric"/(safeLabel(label)+".p12");auto rv=saveP12(path,raw,label);if(rv){EVP_PKEY_free(raw);return rv;}CK_OBJECT_HANDLE before=g.nextObj;addKeyObjects(label,path,raw,nullptr);
 auto commonId=attrstr(priv,qn,CKA_ID,attrstr(pub,pn,CKA_ID,g.objects.at(before).id));
 g.objects.at(before).id=attrstr(priv,qn,CKA_ID,commonId);
 g.objects.at(before+1).id=attrstr(pub,pn,CKA_ID,commonId);
 g.objects.at(before+1).label=attrstr(pub,pn,CKA_LABEL,label);
 rv=persistMetadata(path.string());if(rv)return rv;*qh=before;*ph=before+1;return CKR_OK;}
static CK_RV aesWrap(bool unwrap,CK_MECHANISM_PTR m,Object* wrapping,const unsigned char* in,size_t inlen,unsigned char* out,size_t* outlen){if(!m||!wrapping||wrapping->type!=CKK_AES)return CKR_KEY_TYPE_INCONSISTENT;if(m->mechanism!=CKM_AES_KEY_WRAP&&m->mechanism!=CKM_AES_KEY_WRAP_PAD)return CKR_MECHANISM_INVALID;if(m->pParameter||m->ulParameterLen)return CKR_MECHANISM_PARAM_INVALID;
 if(inlen>static_cast<size_t>(std::numeric_limits<int>::max())-16)return CKR_DATA_LEN_RANGE;
 if(wrapping->secret.size()!=16&&wrapping->secret.size()!=24&&wrapping->secret.size()!=32)return CKR_KEY_SIZE_RANGE;
 if(m->mechanism==CKM_AES_KEY_WRAP&&((inlen%8)!=0||inlen<(unwrap?24:16)))return CKR_DATA_LEN_RANGE;
 if(m->mechanism==CKM_AES_KEY_WRAP_PAD&&(inlen==0||(unwrap&&(inlen<16||inlen%8))))return CKR_DATA_LEN_RANGE;
 std::string cipher="AES-"+std::to_string(wrapping->secret.size()*8)+(m->mechanism==CKM_AES_KEY_WRAP?"-WRAP":"-WRAP-PAD");ossl_ptr<EVP_CIPHER,EVP_CIPHER_free> ci(EVP_CIPHER_fetch(nullptr,cipher.c_str(),nullptr),EVP_CIPHER_free);ossl_ptr<EVP_CIPHER_CTX,EVP_CIPHER_CTX_free> c(EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free);if(!ci||!c)return CKR_DEVICE_ERROR;EVP_CIPHER_CTX_set_flags(c.get(),EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);if(EVP_CipherInit_ex2(c.get(),ci.get(),wrapping->secret.data(),nullptr,unwrap?0:1,nullptr)<=0)return CKR_DEVICE_ERROR;size_t needed=unwrap?inlen:(m->mechanism==CKM_AES_KEY_WRAP?inlen+8:((inlen+7)/8)*8+8);if(!out){*outlen=needed;return CKR_OK;}if(*outlen<needed){*outlen=needed;return CKR_BUFFER_TOO_SMALL;}int a=0,b=0;if(EVP_CipherUpdate(c.get(),out,&a,in,(int)inlen)<=0||EVP_CipherFinal_ex(c.get(),out+a,&b)<=0)return unwrap?CKR_ENCRYPTED_DATA_INVALID:CKR_DEVICE_ERROR;*outlen=a+b;return CKR_OK;}
static std::vector<unsigned char> exportKey(Object* o){
 if(o->cls==CKO_SECRET_KEY)return o->secret;
 if(o->cls!=CKO_PRIVATE_KEY||!o->key)return {};
 ossl_ptr<PKCS8_PRIV_KEY_INFO,PKCS8_PRIV_KEY_INFO_free> info(EVP_PKEY2PKCS8(o->key.get()),PKCS8_PRIV_KEY_INFO_free);
 if(!info)return {};
 int n=i2d_PKCS8_PRIV_KEY_INFO(info.get(),nullptr);if(n<=0)return {};
 std::vector<unsigned char> bytes(n);auto ptr=bytes.data();i2d_PKCS8_PRIV_KEY_INFO(info.get(),&ptr);return bytes;
}
static CK_RV CK_CALL WrapKey(CK_SESSION_HANDLE h,CK_MECHANISM_PTR m,CK_OBJECT_HANDLE wh,CK_OBJECT_HANDLE kh,CK_BYTE_PTR out,CK_ULONG_PTR n){std::scoped_lock l(g.mutex);if(!session(h))return CKR_SESSION_HANDLE_INVALID;if(!n)return CKR_ARGUMENTS_BAD;auto*w=object(wh),*k=object(kh);if(!w||!k)return CKR_KEY_HANDLE_INVALID;auto raw=exportKey(k);if(raw.empty())return CKR_KEY_TYPE_INCONSISTENT;size_t z=*n;auto rv=aesWrap(false,m,w,raw.data(),raw.size(),out,&z);*n=z;return rv;}
static CK_RV CK_CALL UnwrapKey(CK_SESSION_HANDLE h,CK_MECHANISM_PTR m,CK_OBJECT_HANDLE wh,CK_BYTE_PTR in,CK_ULONG inlen,CK_ATTRIBUTE_PTR a,CK_ULONG an,CK_OBJECT_HANDLE_PTR out){std::scoped_lock l(g.mutex);if(!session(h))return CKR_SESSION_HANDLE_INVALID;if(!in||!out)return CKR_ARGUMENTS_BAD;auto*w=object(wh);if(!w)return CKR_KEY_HANDLE_INVALID;size_t z=inlen;std::vector<unsigned char> raw(z);auto rv=aesWrap(true,m,w,in,inlen,raw.data(),&z);if(rv)return rv;raw.resize(z);auto cls=attrulong(a,an,CKA_CLASS).value_or(CKO_SECRET_KEY);std::string label=attrstr(a,an,CKA_LABEL,"unwrapped-key");if(cls==CKO_SECRET_KEY){if(raw.size()!=16&&raw.size()!=24&&raw.size()!=32)return CKR_KEY_SIZE_RANGE;Object o{g.nextObj++,CKO_SECRET_KEY,CKK_AES,label,attrstr(a,an,CKA_ID,std::to_string(g.nextObj)),(g.root/"symmetric"/(safeLabel(label)+".key")).string(),{},raw};rv=saveSecret(o);if(rv)return rv;auto handle=o.h;g.objects.emplace(handle,std::move(o));rv=persistMetadata(g.objects.at(handle).path);if(rv)return rv;*out=handle;return CKR_OK;}const unsigned char*p=raw.data();if(cls!=CKO_PRIVATE_KEY)return CKR_TEMPLATE_INCONSISTENT;
 ossl_ptr<PKCS8_PRIV_KEY_INFO,PKCS8_PRIV_KEY_INFO_free> info(d2i_PKCS8_PRIV_KEY_INFO(nullptr,&p,(long)raw.size()),PKCS8_PRIV_KEY_INFO_free);
 if(!info||p!=raw.data()+raw.size())return CKR_DATA_INVALID;
 EVP_PKEY*k=EVP_PKCS82PKEY(info.get());if(!k)return CKR_DATA_INVALID;fs::path path=g.root/"asymmetric"/(safeLabel(label)+".p12");rv=saveP12(path,k,label);if(rv){EVP_PKEY_free(k);return rv;}CK_OBJECT_HANDLE before=g.nextObj;addKeyObjects(label,path,k,nullptr);
 auto id=attrstr(a,an,CKA_ID,g.objects.at(before).id);
 g.objects.at(before).id=id;g.objects.at(before+1).id=id;
 rv=persistMetadata(path.string());if(rv)return rv;*out=before;return CKR_OK;}
static CK_RV CK_CALL GenerateRandom(CK_SESSION_HANDLE h,CK_BYTE_PTR p,CK_ULONG n){std::scoped_lock l(g.mutex);if(!session(h))return CKR_SESSION_HANDLE_INVALID;if(!p&&n)return CKR_ARGUMENTS_BAD;return RAND_bytes(p,(int)n)==1?CKR_OK:CKR_DEVICE_ERROR;}

// AES-only encryption-based derivation. Policies are intentionally not enforced.
static CK_RV CK_CALL DeriveKey(CK_SESSION_HANDLE h,CK_MECHANISM_PTR m,CK_OBJECT_HANDLE base,
 CK_ATTRIBUTE_PTR attrs,CK_ULONG count,CK_OBJECT_HANDLE_PTR out){
 auto* s=session(h);if(!s)return CKR_SESSION_HANDLE_INVALID;
 if(!m||!out||(!attrs&&count))return CKR_ARGUMENTS_BAD;
 if(m->mechanism!=CKM_AES_ECB_ENCRYPT_DATA)return CKR_MECHANISM_INVALID;
 if(!m->pParameter||m->ulParameterLen!=sizeof(CK_KEY_DERIVATION_STRING_DATA))return CKR_MECHANISM_PARAM_INVALID;
 CK_KEY_DERIVATION_STRING_DATA data;std::memcpy(&data,m->pParameter,sizeof data);
 if(!data.pData)return CKR_MECHANISM_PARAM_INVALID;
 if(!data.ulLen||data.ulLen%16||data.ulLen>static_cast<CK_ULONG>(std::numeric_limits<int>::max()-16))return CKR_DATA_LEN_RANGE;
 auto* master=object(base);if(!master)return CKR_KEY_HANDLE_INVALID;
 if(master->cls!=CKO_SECRET_KEY||master->type!=CKK_AES)return CKR_KEY_TYPE_INCONSISTENT;
 if(master->secret.size()!=16&&master->secret.size()!=24&&master->secret.size()!=32)return CKR_KEY_SIZE_RANGE;
 CK_BBOOL token=CK_FALSE;
 for(CK_ULONG i=0;i<count;++i){
  auto& a=attrs[i];
  for(CK_ULONG j=0;j<i;++j)if(attrs[j].type==a.type)return CKR_TEMPLATE_INCONSISTENT;
  if(!a.pValue&&a.ulValueLen)return CKR_ATTRIBUTE_VALUE_INVALID;
  switch(a.type){
   case CKA_CLASS:case CKA_KEY_TYPE:case CKA_VALUE_LEN:
    if(!a.pValue||a.ulValueLen!=sizeof(CK_ULONG))return CKR_ATTRIBUTE_VALUE_INVALID;break;
   case CKA_TOKEN:case CKA_PRIVATE:case CKA_DERIVE:case CKA_WRAP:case CKA_UNWRAP:
   case CKA_ENCRYPT:case CKA_DECRYPT:case CKA_SIGN:case CKA_VERIFY:case CKA_SENSITIVE:case CKA_EXTRACTABLE:{
    if(!a.pValue||a.ulValueLen!=sizeof(CK_BBOOL))return CKR_ATTRIBUTE_VALUE_INVALID;
    auto value=*static_cast<CK_BBOOL*>(a.pValue);if(value!=CK_TRUE&&value!=CK_FALSE)return CKR_ATTRIBUTE_VALUE_INVALID;
    if(a.type==CKA_TOKEN)token=value;break;
   }
   case CKA_LABEL:case CKA_ID:break;
   case CKA_VALUE:return CKR_TEMPLATE_INCONSISTENT;
   default:return CKR_ATTRIBUTE_TYPE_INVALID;
  }
 }
 if(attrulong(attrs,count,CKA_CLASS).value_or(CKO_SECRET_KEY)!=CKO_SECRET_KEY)return CKR_TEMPLATE_INCONSISTENT;
 auto type=attrulong(attrs,count,CKA_KEY_TYPE),length=attrulong(attrs,count,CKA_VALUE_LEN);
 // Generic-secret derivation is outside this simulator's AES storage model.
 if(!type||!length)return CKR_TEMPLATE_INCOMPLETE;
 if(*type!=CKK_AES)return CKR_TEMPLATE_INCONSISTENT;
 if(*length!=16&&*length!=24&&*length!=32)return CKR_KEY_SIZE_RANGE;
 if(*length>data.ulLen)return CKR_DATA_LEN_RANGE;
 if(token&&!(s->flags&CKF_RW_SESSION))return CKR_SESSION_READ_ONLY;
 std::string cipher="AES-"+std::to_string(master->secret.size()*8)+"-ECB";
 ossl_ptr<EVP_CIPHER,EVP_CIPHER_free> ci(EVP_CIPHER_fetch(nullptr,cipher.c_str(),nullptr),EVP_CIPHER_free);
 ossl_ptr<EVP_CIPHER_CTX,EVP_CIPHER_CTX_free> ctx(EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free);
 if(!ci||!ctx)return CKR_DEVICE_ERROR;
 if(EVP_EncryptInit_ex2(ctx.get(),ci.get(),master->secret.data(),nullptr,nullptr)!=1||EVP_CIPHER_CTX_set_padding(ctx.get(),0)!=1)return CKR_DEVICE_ERROR;
 // Only leading blocks contribute to the requested key; ECB blocks are independent.
 size_t used=((*length+15)/16)*16;
 std::vector<unsigned char> value(used+16);int n=0,tail=0;
 if(EVP_EncryptUpdate(ctx.get(),value.data(),&n,data.pData,(int)used)!=1||EVP_EncryptFinal_ex(ctx.get(),value.data()+n,&tail)!=1)return CKR_DEVICE_ERROR;
 if(n+tail!=(int)used)return CKR_DEVICE_ERROR;
 value.resize(*length);
 Object o;o.h=g.nextObj++;o.cls=CKO_SECRET_KEY;o.type=CKK_AES;
 o.label=attrstr(attrs,count,CKA_LABEL,"derived-"+std::to_string(o.h));
 o.id=attrstr(attrs,count,CKA_ID,std::to_string(o.h));o.secret=std::move(value);
 o.owner=token?0:h;
 if(token){o.path=(g.root/"symmetric"/(safeLabel(o.label)+".key")).string();auto rv=saveSecret(o);if(rv)return rv;}
 auto handle=o.h;g.objects.emplace(handle,std::move(o));
 if(token){auto rv=persistMetadata(g.objects.at(handle).path);if(rv)return rv;}
 *out=handle;return CKR_OK;
}

#include "exports.inc"
