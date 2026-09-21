#include "pkcs11.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

static unsigned checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) throw std::runtime_error(#x); } while (false)
static void rv(CK_RV actual, CK_RV expected, const char* call) {
    ++checks;
    if (actual != expected) {
        std::cerr << call << ": CK_RV=0x" << std::hex << actual
                  << ", expected 0x" << expected << std::dec << '\n';
        throw std::runtime_error(call);
    }
}
#define OK(x) rv((x), CKR_OK, #x)
static CK_FUNCTION_LIST_PTR f;
static CK_SESSION_HANDLE session;
using Bytes = std::vector<CK_BYTE>;
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
static CK_BYTE message[] = {0, 1, 2, 255, 42, 0, 3};
static void openToken() {
    OK(f->C_Initialize(nullptr));
    OK(f->C_OpenSession(1, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &session));
}
static std::vector<CK_OBJECT_HANDLE> find(std::string label, CK_OBJECT_CLASS cls) {
    CK_ATTRIBUTE attrs[] = {{CKA_LABEL, label.data(), (CK_ULONG)label.size()},
                            {CKA_CLASS, &cls, sizeof cls}};
    OK(f->C_FindObjectsInit(session, attrs, 2));
    CK_OBJECT_HANDLE handles[4]; CK_ULONG n = 0;
    OK(f->C_FindObjects(session, handles, 4, &n));
    OK(f->C_FindObjectsFinal(session));
    return {handles, handles + n};
}
static CK_OBJECT_HANDLE one(std::string label, CK_OBJECT_CLASS cls) {
    auto handles = find(label, cls); CHECK(handles.size() == 1); return handles[0];
}
static void attributes(CK_OBJECT_HANDLE key, CK_ULONG parameter) {
    CK_ULONG actual = 0; CK_KEY_TYPE type = 0;
    CK_ATTRIBUTE attrs[] = {{CKA_PARAMETER_SET, &actual, sizeof actual},
                            {CKA_KEY_TYPE, &type, sizeof type}};
    OK(f->C_GetAttributeValue(session, key, attrs, 2));
    CHECK(actual == parameter); CHECK(type == CKK_ML_DSA);
}
static Key readP12(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    CHECK(stream.good());
    std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(stream)), {});
    const unsigned char* p = bytes.data();
    std::unique_ptr<PKCS12, decltype(&PKCS12_free)> container(
        d2i_PKCS12(nullptr, &p, (long)bytes.size()), PKCS12_free);
    CHECK(container != nullptr);
    EVP_PKEY* key = nullptr; X509* cert = nullptr;
    const char* password = std::getenv("HSM_SIM_P12_PASSWORD");
    int result = PKCS12_parse(container.get(), password ? password : "", &key, &cert, nullptr);
    Key owned(key, EVP_PKEY_free); X509_free(cert);
    CHECK(result == 1); CHECK(owned != nullptr); return owned;
}
static void verify(CK_OBJECT_HANDLE pub, Bytes signature) {
    CK_MECHANISM mech{CKM_ML_DSA, nullptr, 0};
    OK(f->C_VerifyInit(session, &mech, pub));
    OK(f->C_Verify(session, message, sizeof message, signature.data(), (CK_ULONG)signature.size()));
}
static void exercise(CK_OBJECT_HANDLE priv, CK_OBJECT_HANDLE pub, EVP_PKEY* independent, size_t size) {
    CK_MECHANISM mech{CKM_ML_DSA, nullptr, 0};
    OK(f->C_SignInit(session, &mech, priv)); CK_ULONG n = 0;
    OK(f->C_Sign(session, message, sizeof message, nullptr, &n)); CHECK(n == size);
    Bytes sig(n); CK_ULONG small = n - 1;
    rv(f->C_Sign(session, message, sizeof message, sig.data(), &small), CKR_BUFFER_TOO_SMALL, "Sign small buffer");
    CHECK(small == n);
    OK(f->C_Sign(session, message, sizeof message, sig.data(), &n)); sig.resize(n);
    verify(pub, sig);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    CHECK(ctx != nullptr);
    CHECK(EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, independent) == 1);
    CHECK(EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), message, sizeof message) == 1);
    CHECK(EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, independent) == 1);
    size_t len = sig.size();
    CHECK(EVP_DigestSign(ctx.get(), sig.data(), &len, message, sizeof message) == 1);
    sig.resize(len); verify(pub, sig);
    sig[0] ^= 1;
    OK(f->C_VerifyInit(session, &mech, pub));
    rv(f->C_Verify(session, message, sizeof message, sig.data(), (CK_ULONG)sig.size()), CKR_SIGNATURE_INVALID, "Tampered signature");
    OK(f->C_SignInit(session, &mech, priv));
    OK(f->C_SignUpdate(session, message, 2));
    OK(f->C_SignUpdate(session, message + 2, sizeof message - 2));
    n = 0; OK(f->C_SignFinal(session, nullptr, &n)); sig.resize(n);
    small = n - 1;
    rv(f->C_SignFinal(session, sig.data(), &small), CKR_BUFFER_TOO_SMALL, "SignFinal small buffer");
    OK(f->C_SignFinal(session, sig.data(), &n)); sig.resize(n); verify(pub, sig);
    OK(f->C_VerifyInit(session, &mech, pub));
    OK(f->C_VerifyUpdate(session, message, 3));
    OK(f->C_VerifyUpdate(session, message + 3, sizeof message - 3));
    OK(f->C_VerifyFinal(session, sig.data(), (CK_ULONG)sig.size()));
}
int main() {
    try {
        std::cout << OpenSSL_version(OPENSSL_VERSION) << std::endl;
        CHECK(OpenSSL_version_num() >= 0x30500000UL);
        const char* rootEnv = std::getenv("HSM_SIM_DATA_DIR"); CHECK(rootEnv && *rootEnv);
        std::filesystem::path root(rootEnv);
        // Run only through the isolated CTest token runner.
        CHECK(!std::filesystem::exists(root) || std::filesystem::is_empty(root));
        CHECK(C_GetFunctionList(&f) == CKR_OK); openToken();
        CK_ULONG aesLen = 32; std::string aesLabel = "mldsa-wrapping";
        CK_ATTRIBUTE aesAttrs[] = {{CKA_LABEL, aesLabel.data(), (CK_ULONG)aesLabel.size()}, {CKA_VALUE_LEN, &aesLen, sizeof aesLen}};
        CK_MECHANISM aesGen{CKM_AES_KEY_GEN, nullptr, 0}; CK_OBJECT_HANDLE aes;
        OK(f->C_GenerateKey(session, &aesGen, aesAttrs, 2, &aes));
        const CK_ULONG params[] = {CKP_ML_DSA_44, CKP_ML_DSA_65, CKP_ML_DSA_87};
        const char* names[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
        const size_t sizes[] = {2420, 3309, 4627};
        for (int i = 0; i < 3; ++i) {
            std::cout << "Testing " << names[i] << std::endl;
            std::string label = names[i]; CK_ULONG parameter = params[i];
            CK_ATTRIBUTE attrs[] = {{CKA_LABEL, label.data(), (CK_ULONG)label.size()}, {CKA_PARAMETER_SET, &parameter, sizeof parameter}};
            CK_MECHANISM gen{CKM_ML_DSA_KEY_PAIR_GEN, nullptr, 0}; CK_OBJECT_HANDLE pub, priv;
            OK(f->C_GenerateKeyPair(session, &gen, attrs, 2, attrs, 2, &pub, &priv));
            attributes(pub, parameter); attributes(priv, parameter);
            auto independent = readP12(root / "asymmetric" / (label + ".p12"));
            CHECK(EVP_PKEY_is_a(independent.get(), names[i]) == 1);
            exercise(priv, pub, independent.get(), sizes[i]);
            OK(f->C_Finalize(nullptr)); openToken();
            aes = one(aesLabel, CKO_SECRET_KEY); pub = one(label, CKO_PUBLIC_KEY); priv = one(label, CKO_PRIVATE_KEY);
            attributes(priv, parameter); exercise(priv, pub, independent.get(), sizes[i]);
            // RFC3394 requires an aligned PKCS#8 payload; RFC5649 accepts any length.
            std::unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)> info(EVP_PKEY2PKCS8(independent.get()), PKCS8_PRIV_KEY_INFO_free);
            CHECK(info != nullptr); int encodedSize = i2d_PKCS8_PRIV_KEY_INFO(info.get(), nullptr); CHECK(encodedSize > 0);
            for (auto mechanism : {CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_PAD}) {
                CK_MECHANISM wrap{mechanism, nullptr, 0}; CK_ULONG n = 0;
                if (mechanism == CKM_AES_KEY_WRAP && (encodedSize < 16 || encodedSize % 8)) {
                    rv(f->C_WrapKey(session, &wrap, aes, priv, nullptr, &n), CKR_DATA_LEN_RANGE, "Unaligned RFC3394 payload");
                    std::cout << "  AES-KW: unaligned PKCS#8 correctly rejected; using AES-KWP" << std::endl;
                    continue;
                }
                OK(f->C_WrapKey(session, &wrap, aes, priv, nullptr, &n)); CHECK(n > 0);
                Bytes wrapped(n); CK_ULONG small = n - 1;
                rv(f->C_WrapKey(session, &wrap, aes, priv, wrapped.data(), &small), CKR_BUFFER_TOO_SMALL, "Wrap small buffer"); CHECK(small == n);
                OK(f->C_WrapKey(session, &wrap, aes, priv, wrapped.data(), &n)); wrapped.resize(n);
                std::string restored = label + (mechanism == CKM_AES_KEY_WRAP ? "-kw" : "-kwp");
                CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY; CK_KEY_TYPE type = CKK_ML_DSA;
                CK_ATTRIBUTE unwrapAttrs[] = {{CKA_CLASS, &cls, sizeof cls}, {CKA_LABEL, restored.data(), (CK_ULONG)restored.size()}, {CKA_KEY_TYPE, &type, sizeof type}, {CKA_PARAMETER_SET, &parameter, sizeof parameter}};
                CK_OBJECT_HANDLE restoredPriv = 0;
                Bytes corrupt = wrapped; corrupt[0] ^= 1;
                CHECK(f->C_UnwrapKey(session, &wrap, aes, corrupt.data(), (CK_ULONG)corrupt.size(), unwrapAttrs, 4, &restoredPriv) != CKR_OK);
                CHECK(find(restored, CKO_PRIVATE_KEY).empty());
                OK(f->C_DestroyObject(session, priv));
                CHECK(find(label, CKO_PRIVATE_KEY).empty()); CHECK(find(label, CKO_PUBLIC_KEY).empty());
                OK(f->C_UnwrapKey(session, &wrap, aes, wrapped.data(), (CK_ULONG)wrapped.size(), unwrapAttrs, 4, &restoredPriv));
                auto restoredPub = one(restored, CKO_PUBLIC_KEY);
                attributes(restoredPriv, parameter); exercise(restoredPriv, restoredPub, independent.get(), sizes[i]);
                OK(f->C_Finalize(nullptr)); openToken();
                aes = one(aesLabel, CKO_SECRET_KEY); priv = one(restored, CKO_PRIVATE_KEY); pub = one(restored, CKO_PUBLIC_KEY);
                attributes(priv, parameter); attributes(pub, parameter);
                exercise(priv, pub, independent.get(), sizes[i]);
                auto diskKey = readP12(root / "asymmetric" / (restored + ".p12"));
                CHECK(EVP_PKEY_eq(independent.get(), diskKey.get()) == 1);
                label = restored;
            }
            std::cout << names[i] << " PASS" << std::endl;
        }
        OK(f->C_Finalize(nullptr));
        std::cout << checks << " ML-DSA checks passed\n"; return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL after " << checks << " checks: " << e.what() << '\n';
        ERR_print_errors_fp(stderr); if (f) f->C_Finalize(nullptr); return 1;
    }
}
