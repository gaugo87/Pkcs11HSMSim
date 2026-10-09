#include "pkcs11.h"
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <openssl/pkcs12.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
static unsigned checks = 0;
#define CHECK(expression)                                                                          \
    do                                                                                             \
    {                                                                                              \
        ++checks;                                                                                  \
        if (!(expression))                                                                         \
            throw std::runtime_error(                                                              \
                std::string("line ") + std::to_string(__LINE__) + ": " + #expression);             \
    } while (false)
#define EXPECT(expression, expected)                                                               \
    do                                                                                             \
    {                                                                                              \
        const auto actual = (expression);                                                          \
        ++checks;                                                                                  \
        if (actual != (expected))                                                                  \
            throw std::runtime_error(std::string("line ") + std::to_string(__LINE__) + ": " +      \
                #expression + " returned " + std::to_string(actual) + ", expected " +              \
                std::to_string(expected));                                                         \
    } while (false)

static CK_UTF8CHAR_PTR pin(std::string& value)
{
    return reinterpret_cast<CK_UTF8CHAR_PTR>(value.data());
}

static CK_RV login(CK_SESSION_HANDLE session, std::string value, CK_USER_TYPE role = CKU_USER)
{
    return C_Login(session, role, pin(value), static_cast<CK_ULONG>(value.size()));
}

static CK_RV setPin(CK_SESSION_HANDLE session, std::string oldPin, std::string newPin)
{
    return C_SetPIN(session, pin(oldPin), static_cast<CK_ULONG>(oldPin.size()), pin(newPin),
        static_cast<CK_ULONG>(newPin.size()));
}

static CK_RV initPin(CK_SESSION_HANDLE session, std::string value)
{
    return C_InitPIN(session, pin(value), static_cast<CK_ULONG>(value.size()));
}

static void writeText(const fs::path& path, const std::string& value)
{
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output << value;
    output.close();
    CHECK(output.good());
}

static CK_SESSION_HANDLE open(CK_SLOT_ID slot, bool readWrite = true)
{
    CK_SESSION_HANDLE session = 0;
    EXPECT(C_OpenSession(slot, CKF_SERIAL_SESSION | (readWrite ? CKF_RW_SESSION : 0), nullptr,
               nullptr, &session),
        CKR_OK);
    return session;
}

static CK_STATE state(CK_SESSION_HANDLE session, CK_SLOT_ID slot)
{
    CK_SESSION_INFO info{};
    EXPECT(C_GetSessionInfo(session, &info), CKR_OK);
    CHECK(info.slotID == slot);
    return info.state;
}

static std::vector<CK_OBJECT_HANDLE> find(
    CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attributes = nullptr, CK_ULONG count = 0)
{
    EXPECT(C_FindObjectsInit(session, attributes, count), CKR_OK);
    std::vector<CK_OBJECT_HANDLE> result;
    CK_OBJECT_HANDLE handle;
    CK_ULONG found;
    do
    {
        EXPECT(C_FindObjects(session, &handle, 1, &found), CKR_OK);
        if (found)
        {
            result.push_back(handle);
        }
    } while (found);
    EXPECT(C_FindObjectsFinal(session), CKR_OK);
    return result;
}

static CK_OBJECT_HANDLE findKey(CK_SESSION_HANDLE session, std::string label, CK_OBJECT_CLASS cls)
{
    CK_ATTRIBUTE attributes[] = {{CKA_LABEL, label.data(), static_cast<CK_ULONG>(label.size())},
        {CKA_CLASS, &cls, sizeof(cls)}};
    const auto result = find(session, attributes, 2);
    CHECK(result.size() == 1);
    return result.front();
}

static CK_OBJECT_HANDLE aes(
    CK_SESSION_HANDLE session, std::string label, bool token = true, CK_RV expected = CKR_OK)
{
    CK_BBOOL persistent = token ? CK_TRUE : CK_FALSE;
    CK_ULONG length = 32;
    CK_ATTRIBUTE attributes[] = {{CKA_LABEL, label.data(), static_cast<CK_ULONG>(label.size())},
        {CKA_VALUE_LEN, &length, sizeof(length)}, {CKA_TOKEN, &persistent, sizeof(persistent)}};
    CK_MECHANISM mechanism{CKM_AES_KEY_GEN, nullptr, 0};
    CK_OBJECT_HANDLE key = 0;
    EXPECT(C_GenerateKey(session, &mechanism, attributes, 3, &key), expected);
    return key;
}

static std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> rsa(CK_SESSION_HANDLE session)
{
    CK_MECHANISM mechanism{CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_ULONG bits = 2048;
    char label[] = "same-rsa";
    CK_ATTRIBUTE publicAttributes[] = {{CKA_MODULUS_BITS, &bits, sizeof(bits)}};
    CK_ATTRIBUTE privateAttributes[] = {{CKA_LABEL, label, sizeof(label) - 1}};
    CK_OBJECT_HANDLE pub, priv;
    EXPECT(C_GenerateKeyPair(
               session, &mechanism, publicAttributes, 1, privateAttributes, 1, &pub, &priv),
        CKR_OK);
    return {pub, priv};
}

static void signAndVerify(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv, CK_OBJECT_HANDLE pub)
{
    CK_MECHANISM mechanism{CKM_SHA256_RSA_PKCS, nullptr, 0};
    CK_BYTE message[] = {1, 2, 3, 4};
    EXPECT(C_SignInit(session, &mechanism, priv), CKR_OK);
    CK_ULONG size = 0;
    EXPECT(C_Sign(session, message, sizeof(message), nullptr, &size), CKR_OK);
    std::vector<CK_BYTE> signature(size);
    EXPECT(C_Sign(session, message, sizeof(message), signature.data(), &size), CKR_OK);
    EXPECT(C_VerifyInit(session, &mechanism, pub), CKR_OK);
    EXPECT(C_Verify(session, message, sizeof(message), signature.data(), size), CKR_OK);
}

static std::vector<CK_BYTE> wrap(
    CK_SESSION_HANDLE session, CK_OBJECT_HANDLE master, CK_OBJECT_HANDLE key)
{
    CK_MECHANISM mechanism{CKM_AES_KEY_WRAP_PAD, nullptr, 0};
    CK_ULONG size = 0;
    EXPECT(C_WrapKey(session, &mechanism, master, key, nullptr, &size), CKR_OK);
    std::vector<CK_BYTE> output(size);
    EXPECT(C_WrapKey(session, &mechanism, master, key, output.data(), &size), CKR_OK);
    output.resize(size);
    return output;
}

static CK_OBJECT_HANDLE unwrap(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE master,
    std::vector<CK_BYTE>& wrapped, CK_OBJECT_CLASS cls, std::string label)
{
    CK_MECHANISM mechanism{CKM_AES_KEY_WRAP_PAD, nullptr, 0};
    CK_ATTRIBUTE attributes[] = {{CKA_CLASS, &cls, sizeof(cls)},
        {CKA_LABEL, label.data(), static_cast<CK_ULONG>(label.size())}};
    CK_OBJECT_HANDLE key;
    EXPECT(C_UnwrapKey(session, &mechanism, master, wrapped.data(),
               static_cast<CK_ULONG>(wrapped.size()), attributes, 2, &key),
        CKR_OK);
    return key;
}

static CK_RV derive(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE master, CK_OBJECT_HANDLE* key)
{
    CK_BYTE context[32] = {1, 2, 3};
    CK_KEY_DERIVATION_STRING_DATA data{context, sizeof(context)};
    CK_MECHANISM mechanism{CKM_AES_ECB_ENCRYPT_DATA, &data, sizeof(data)};
    CK_KEY_TYPE type = CKK_AES;
    CK_ULONG length = 16;
    CK_BBOOL yes = CK_TRUE;
    char label[] = "derived";
    CK_ATTRIBUTE attributes[] = {{CKA_KEY_TYPE, &type, sizeof(type)},
        {CKA_VALUE_LEN, &length, sizeof(length)}, {CKA_LABEL, label, sizeof(label) - 1},
        {CKA_TOKEN, &yes, sizeof(yes)}};
    return C_DeriveKey(session, &mechanism, master, attributes, 4, key);
}

static std::vector<CK_BYTE> value(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
    CK_ATTRIBUTE attribute{CKA_VALUE, nullptr, 0};
    EXPECT(C_GetAttributeValue(session, key, &attribute, 1), CKR_OK);
    std::vector<CK_BYTE> result(attribute.ulValueLen);
    attribute.pValue = result.data();
    EXPECT(C_GetAttributeValue(session, key, &attribute, 1), CKR_OK);
    return result;
}

static void checkPkcs12(const fs::path& path, const std::string& password)
{
    std::ifstream input(path, std::ios::binary);
    std::vector<unsigned char> der((std::istreambuf_iterator<char>(input)), {});
    CHECK(!der.empty());
    const auto* cursor = der.data();
    PKCS12* container = d2i_PKCS12(nullptr, &cursor, static_cast<long>(der.size()));
    CHECK(container);
    // OpenSSL receives memory only, avoiding the Windows CRT applink dependency.
    CHECK(PKCS12_verify_mac(container, password.c_str(), -1) == 1);
    CHECK(PKCS12_verify_mac(container, "wrong", -1) == 0);
    EVP_PKEY* key = nullptr;
    X509* certificate = nullptr;
    CHECK(PKCS12_parse(container, password.c_str(), &key, &certificate, nullptr) == 1);
    CHECK(key);
    EVP_PKEY_free(key);
    X509_free(certificate);
    PKCS12_free(container);
}

static void testSlots(const fs::path& root)
{
    writeText(root / "0_DEVELOPMENT" / "pin.txt",
        "\xEF\xBB\xBF"
        "1234\r\n");
    writeText(root / "0_DEVELOPMENT" / "so-pin.txt", "admin0\n");
    writeText(root / "0_DEVELOPMENT" / "p12-password.txt", "container0\n");
    writeText(root / "7_INTEGRATION_TEST" / "pin.txt", "5678");
    writeText(root / "7_INTEGRATION_TEST" / "so-pin.txt", "admin7");
    writeText(root / "7_INTEGRATION_TEST" / "p12-password.txt", "container7");
    writeText(root / "9_INITIALIZE" / "so-pin.txt", "admin9");
    fs::create_directories(root / "ignored-directory");
    EXPECT(C_Initialize(nullptr), CKR_OK);
    CK_ULONG count = 0;
    EXPECT(C_GetSlotList(CK_TRUE, nullptr, &count), CKR_OK);
    CHECK(count == 3);
    CK_SLOT_ID slots[3] = {99, 99, 99};
    count = 1;
    EXPECT(C_GetSlotList(CK_TRUE, slots, &count), CKR_BUFFER_TOO_SMALL);
    CHECK(count == 3 && slots[0] == 99);
    EXPECT(C_GetSlotList(CK_FALSE, slots, &count), CKR_OK);
    CHECK(slots[0] == 0 && slots[1] == 7 && slots[2] == 9);
    CK_TOKEN_INFO token{};
    EXPECT(C_GetTokenInfo(7, &token), CKR_OK);
    CHECK(std::string(reinterpret_cast<char*>(token.label), 17) == "INTEGRATION_TEST ");
    CHECK(token.flags & CKF_LOGIN_REQUIRED);
    CHECK(token.flags & CKF_USER_PIN_INITIALIZED);
    EXPECT(C_GetTokenInfo(9, &token), CKR_OK);
    CHECK(!(token.flags & CKF_USER_PIN_INITIALIZED));
    CK_SLOT_INFO slotInfo{};
    EXPECT(C_GetSlotInfo(7, &slotInfo), CKR_OK);
    CHECK(std::string(reinterpret_cast<char*>(slotInfo.slotDescription), 16) == "INTEGRATION_TEST");
    EXPECT(C_GetSlotInfo(1, &slotInfo), CKR_SLOT_ID_INVALID);
    EXPECT(C_GetTokenInfo(1, &token), CKR_SLOT_ID_INVALID);
    EXPECT(C_GetMechanismList(7, nullptr, &count), CKR_OK);
    CHECK(count > 0);
    EXPECT(C_GetMechanismList(1, nullptr, &count), CKR_SLOT_ID_INVALID);
    CK_MECHANISM_INFO mechanismInfo{};
    EXPECT(C_GetMechanismInfo(0, CKM_AES_KEY_WRAP_PAD, &mechanismInfo), CKR_OK);
    EXPECT(C_GetMechanismInfo(1, CKM_AES_KEY_WRAP_PAD, &mechanismInfo), CKR_SLOT_ID_INVALID);
    CK_SESSION_HANDLE invalid;
    EXPECT(C_OpenSession(1, CKF_SERIAL_SESSION, nullptr, nullptr, &invalid), CKR_SLOT_ID_INVALID);
    EXPECT(C_CloseAllSessions(1), CKR_SLOT_ID_INVALID);
    auto s0 = open(0), ro0 = open(0, false), s7 = open(7), ro7 = open(7, false), s9 = open(9);
    EXPECT(C_GetTokenInfo(0, &token), CKR_OK);
    CHECK(token.ulSessionCount == 2 && token.ulRwSessionCount == 1);
    CHECK(state(s0, 0) == CKS_RW_PUBLIC_SESSION);
    aes(s0, "forbidden", true, CKR_USER_NOT_LOGGED_IN);
    EXPECT(login(s0, "bad"), CKR_PIN_INCORRECT);
    EXPECT(C_Login(s0, CKU_USER, nullptr, 4), CKR_ARGUMENTS_BAD);
    EXPECT(login(s0, "1234", CKU_CONTEXT_SPECIFIC), CKR_USER_TYPE_INVALID);
    EXPECT(login(s0, "1234"), CKR_OK);
    EXPECT(login(ro0, "1234"), CKR_USER_ALREADY_LOGGED_IN);
    EXPECT(login(s0, "admin0", CKU_SO), CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
    CHECK(state(ro0, 0) == CKS_RO_USER_FUNCTIONS);
    CHECK(state(s7, 7) == CKS_RW_PUBLIC_SESSION);
    EXPECT(login(s7, "1234"), CKR_PIN_INCORRECT);
    EXPECT(login(s7, "5678"), CKR_OK);

    auto master0 = aes(s0, "same-master"), master7 = aes(s7, "same-master");
    CHECK(master0 != master7);
    auto [pub0, priv0] = rsa(s0);
    auto [pub7, priv7] = rsa(s7);
    signAndVerify(s0, priv0, pub0);
    signAndVerify(s7, priv7, pub7);
    CHECK(find(s0).size() == 3 && find(s7).size() == 3);
    CK_ATTRIBUTE label{CKA_LABEL, nullptr, 0};
    EXPECT(C_GetAttributeValue(s0, master7, &label, 1), CKR_OBJECT_HANDLE_INVALID);
    EXPECT(C_SetAttributeValue(s0, master7, nullptr, 0), CKR_OBJECT_HANDLE_INVALID);
    EXPECT(C_DestroyObject(s0, pub7), CKR_OBJECT_HANDLE_INVALID);
    CK_MECHANISM sign{CKM_SHA256_RSA_PKCS, nullptr, 0};
    EXPECT(C_SignInit(s0, &sign, priv7), CKR_KEY_HANDLE_INVALID);
    EXPECT(C_VerifyInit(s0, &sign, pub7), CKR_KEY_HANDLE_INVALID);
    CK_MECHANISM wrapping{CKM_AES_KEY_WRAP_PAD, nullptr, 0};
    CK_ULONG size = 0;
    EXPECT(C_WrapKey(s0, &wrapping, master0, priv7, nullptr, &size), CKR_KEY_HANDLE_INVALID);
    EXPECT(C_WrapKey(s0, &wrapping, master7, priv0, nullptr, &size), CKR_KEY_HANDLE_INVALID);
    auto wrappedPrivate = wrap(s0, master0, priv0);
    CK_OBJECT_HANDLE handle = 0;
    EXPECT(C_UnwrapKey(s0, &wrapping, master7, wrappedPrivate.data(),
               static_cast<CK_ULONG>(wrappedPrivate.size()), nullptr, 0, &handle),
        CKR_KEY_HANDLE_INVALID);
    EXPECT(derive(s0, master7, &handle), CKR_KEY_HANDLE_INVALID);
    CK_OBJECT_HANDLE derived0, derived7;
    EXPECT(derive(s0, master0, &derived0), CKR_OK);
    EXPECT(derive(s7, master7, &derived7), CKR_OK);
    CHECK(value(s0, derived0).size() == 16);
    auto wrappedSecret = wrap(s0, derived0, master0);
    auto restoredSecret = unwrap(s0, derived0, wrappedSecret, CKO_SECRET_KEY, "restored-master");
    CHECK(value(s0, restoredSecret) == value(s0, master0));
    auto restoredPrivate = unwrap(s0, master0, wrappedPrivate, CKO_PRIVATE_KEY, "restored-rsa");
    signAndVerify(s0, restoredPrivate, pub0);
    checkPkcs12(root / "0_DEVELOPMENT" / "asymmetric" / "same-rsa.p12", "container0");
    checkPkcs12(root / "7_INTEGRATION_TEST" / "asymmetric" / "same-rsa.p12", "container7");
    CHECK(fs::exists(root / "0_DEVELOPMENT" / "symmetric" / "derived.key"));
    CHECK(fs::exists(root / "7_INTEGRATION_TEST" / "symmetric" / "derived.key"));
    CHECK(!fs::exists(root / "symmetric"));

    auto temporary0 = aes(s0, "temporary", false), temporary7 = aes(s7, "temporary", false);
    EXPECT(C_GetAttributeValue(ro0, temporary0, &label, 1), CKR_OK);
    EXPECT(C_SignInit(s0, &sign, priv0), CKR_OK);
    EXPECT(C_SignInit(s7, &sign, priv7), CKR_OK);
    EXPECT(C_Logout(ro0), CKR_OK);
    CHECK(state(s0, 0) == CKS_RW_PUBLIC_SESSION);
    CHECK(state(s7, 7) == CKS_RW_USER_FUNCTIONS);
    EXPECT(C_SignFinal(s0, nullptr, &size), CKR_OPERATION_NOT_INITIALIZED);
    EXPECT(C_SignFinal(s7, nullptr, &size), CKR_OK);
    std::vector<CK_BYTE> signature(size);
    EXPECT(C_SignFinal(s7, signature.data(), &size), CKR_OK);
    EXPECT(C_GetAttributeValue(s0, temporary0, &label, 1), CKR_OBJECT_HANDLE_INVALID);
    EXPECT(C_GetAttributeValue(s7, temporary7, &label, 1), CKR_OK);
    EXPECT(C_GetAttributeValue(s0, master0, &label, 1), CKR_USER_NOT_LOGGED_IN);
    EXPECT(C_GetAttributeValue(s0, priv0, &label, 1), CKR_USER_NOT_LOGGED_IN);
    EXPECT(C_GetAttributeValue(s0, pub0, &label, 1), CKR_OK);
    EXPECT(C_SignInit(s0, &sign, priv0), CKR_USER_NOT_LOGGED_IN);
    EXPECT(C_WrapKey(s0, &wrapping, master0, priv0, nullptr, &size), CKR_USER_NOT_LOGGED_IN);
    EXPECT(derive(s0, master0, &handle), CKR_USER_NOT_LOGGED_IN);
    EXPECT(C_UnwrapKey(s0, &wrapping, master0, wrappedPrivate.data(),
               static_cast<CK_ULONG>(wrappedPrivate.size()), nullptr, 0, &handle),
        CKR_USER_NOT_LOGGED_IN);
    EXPECT(C_DestroyObject(s0, pub0), CKR_USER_NOT_LOGGED_IN);
    EXPECT(C_SetAttributeValue(s0, pub0, nullptr, 0), CKR_USER_NOT_LOGGED_IN);
    CHECK(find(s0).size() == 2); // Public halves of the original and restored RSA keys.
    EXPECT(C_Logout(s0), CKR_USER_NOT_LOGGED_IN);

    // SO state is token-wide; read-only sessions on OTHER slots do not block it.
    EXPECT(login(ro0, "admin0", CKU_SO), CKR_SESSION_READ_ONLY);
    EXPECT(login(s0, "admin0", CKU_SO), CKR_SESSION_READ_ONLY_EXISTS);
    EXPECT(C_CloseSession(ro0), CKR_OK);
    EXPECT(login(s0, "admin0", CKU_SO), CKR_OK);
    CHECK(state(s0, 0) == CKS_RW_SO_FUNCTIONS);
    EXPECT(C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &invalid),
        CKR_SESSION_READ_WRITE_SO_EXISTS);
    aes(s0, "forbidden-so", true, CKR_USER_NOT_LOGGED_IN);
    EXPECT(setPin(s0, "admin0", "admin0-new"), CKR_OK);
    EXPECT(initPin(s0, "new-user0"), CKR_OK);
    EXPECT(C_Logout(s0), CKR_OK);
    EXPECT(login(s0, "1234"), CKR_PIN_INCORRECT);
    EXPECT(login(s0, "new-user0"), CKR_OK);
    EXPECT(initPin(s0, "forbidden"), CKR_USER_NOT_LOGGED_IN);
    writeText(root / "0_DEVELOPMENT" / "pin.txt.tmp", "occupied");
    EXPECT(setPin(s0, "new-user0", "lost"), CKR_DEVICE_ERROR);
    fs::remove(root / "0_DEVELOPMENT" / "pin.txt.tmp");
    EXPECT(setPin(s0, "bad", "lost"), CKR_PIN_INCORRECT);
    EXPECT(setPin(s0, "new-user0", std::string(257, 'x')), CKR_PIN_LEN_RANGE);
    EXPECT(setPin(s0, "new-user0", "bad\nvalue"), CKR_PIN_INVALID);
    EXPECT(setPin(s0, "new-user0", std::string("bad\0value", 9)), CKR_PIN_INVALID);
    EXPECT(setPin(ro7, "5678", "lost"), CKR_SESSION_READ_ONLY);
    EXPECT(setPin(s0, "new-user0", "final0"), CKR_OK);
    EXPECT(C_CloseAllSessions(0), CKR_OK);
    EXPECT(C_GetSessionInfo(s0, nullptr), CKR_SESSION_HANDLE_INVALID);
    CHECK(state(s7, 7) == CKS_RW_USER_FUNCTIONS);
    EXPECT(C_GetAttributeValue(s7, temporary7, &label, 1), CKR_OK);
    s0 = open(0);
    CHECK(state(s0, 0) == CKS_RW_PUBLIC_SESSION);
    EXPECT(login(s0, "final0"), CKR_OK);
    signAndVerify(s0, priv0, pub0);

    // Initialize an unset PIN via SO; an explicitly empty PIN still requires login.
    EXPECT(login(s9, ""), CKR_USER_PIN_NOT_INITIALIZED);
    aes(s9, "forbidden", true, CKR_USER_NOT_LOGGED_IN);
    EXPECT(login(s9, "admin9", CKU_SO), CKR_OK);
    EXPECT(initPin(s9, ""), CKR_OK);
    EXPECT(C_GetTokenInfo(9, &token), CKR_OK);
    CHECK(token.flags & CKF_USER_PIN_INITIALIZED);
    CHECK(token.flags & CKF_LOGIN_REQUIRED);
    EXPECT(C_Logout(s9), CKR_OK);
    EXPECT(login(s9, "not-empty"), CKR_PIN_INCORRECT);
    EXPECT(login(s9, ""), CKR_OK);
    EXPECT(C_CloseSession(s9), CKR_OK);
    s9 = open(9);
    CHECK(state(s9, 9) == CKS_RW_PUBLIC_SESSION);
    // C_SetPIN is also permitted in a RW public session with the old USER PIN.
    EXPECT(setPin(s9, "", "nine"), CKR_OK);
    EXPECT(C_Finalize(nullptr), CKR_OK);

    EXPECT(C_Initialize(nullptr), CKR_OK);
    s0 = open(0);
    s7 = open(7);
    s9 = open(9);
    EXPECT(login(s0, "new-user0"), CKR_PIN_INCORRECT);
    EXPECT(login(s0, "final0"), CKR_OK);
    EXPECT(login(s7, "5678"), CKR_OK);
    EXPECT(login(s9, "nine"), CKR_OK);
    pub0 = findKey(s0, "same-rsa", CKO_PUBLIC_KEY);
    priv0 = findKey(s0, "same-rsa", CKO_PRIVATE_KEY);
    pub7 = findKey(s7, "same-rsa", CKO_PUBLIC_KEY);
    priv7 = findKey(s7, "same-rsa", CKO_PRIVATE_KEY);
    signAndVerify(s0, priv0, pub0);
    signAndVerify(s7, priv7, pub7);
    CHECK(findKey(s0, "derived", CKO_SECRET_KEY) != findKey(s7, "derived", CKO_SECRET_KEY));
    EXPECT(C_Logout(s0), CKR_OK);
    EXPECT(login(s0, "admin0", CKU_SO), CKR_PIN_INCORRECT);
    EXPECT(login(s0, "admin0-new", CKU_SO), CKR_OK);
    EXPECT(C_Finalize(nullptr), CKR_OK);
}

static void testInvalidLayouts(const fs::path& root)
{
    fs::create_directories(root / "00_DUPLICATE");
    EXPECT(C_Initialize(nullptr), CKR_DEVICE_ERROR);
    CK_ULONG count;
    EXPECT(C_GetSlotList(CK_TRUE, nullptr, &count), CKR_CRYPTOKI_NOT_INITIALIZED);
    fs::remove_all(root / "00_DUPLICATE");
    fs::create_directories(root / "123_");
    EXPECT(C_Initialize(nullptr), CKR_DEVICE_ERROR);
    fs::remove_all(root / "123_");
    const auto overflow = root / "999999999999999999999999999_OVERFLOW";
    fs::create_directories(overflow);
    EXPECT(C_Initialize(nullptr), CKR_DEVICE_ERROR);
    fs::remove_all(overflow);
    fs::create_directories(root / "symmetric");
    EXPECT(C_Initialize(nullptr), CKR_DEVICE_ERROR);
    fs::remove_all(root / "symmetric");
    writeText(root / "9_INITIALIZE" / "pin.txt", "two\nlines");
    EXPECT(C_Initialize(nullptr), CKR_DEVICE_ERROR);
    writeText(root / "9_INITIALIZE" / "pin.txt", "nine");
    EXPECT(C_Initialize(nullptr), CKR_OK);
    EXPECT(C_Finalize(nullptr), CKR_OK);
}

static void setEnvironment(const char* name, const std::string& value)
{
#ifdef _WIN32
    CHECK(_putenv_s(name, value.c_str()) == 0);
#else
    CHECK(setenv(name, value.c_str(), 1) == 0);
#endif
}

static void testFallbackAndLegacy(const fs::path& root)
{
    const auto configuredRoot = root / "configuration-cases";
    writeText(configuredRoot / "0_FALLBACK" / "symmetric" / "imported.key",
        "00112233445566778899AABBCCDDEEFF");
    writeText(configuredRoot / "1_OVERRIDE" / "pin.txt", "override");
    writeText(configuredRoot / "2_EMPTY" / "pin.txt", "");
    setEnvironment("HSM_SIM_DATA_DIR", configuredRoot.string());
    setEnvironment("HSM_SIM_PIN", "fallback");
    EXPECT(C_Initialize(nullptr), CKR_OK);
    auto fallback = open(0), overrideSession = open(1), empty = open(2);
    EXPECT(login(fallback, "fallback"), CKR_OK);
    CHECK(findKey(fallback, "imported", CKO_SECRET_KEY) != 0);
    EXPECT(login(overrideSession, "fallback"), CKR_PIN_INCORRECT);
    EXPECT(login(overrideSession, "override"), CKR_OK);
    EXPECT(login(empty, "fallback"), CKR_PIN_INCORRECT);
    EXPECT(login(empty, ""), CKR_OK);
    EXPECT(setPin(fallback, "fallback", "persisted"), CKR_OK);
    EXPECT(C_Finalize(nullptr), CKR_OK);
    EXPECT(C_Initialize(nullptr), CKR_OK);
    fallback = open(0);
    EXPECT(login(fallback, "fallback"), CKR_PIN_INCORRECT);
    EXPECT(login(fallback, "persisted"), CKR_OK);
    EXPECT(C_Finalize(nullptr), CKR_OK);

    const auto legacyRoot = root / "legacy-case";
    fs::create_directories(legacyRoot);
    setEnvironment("HSM_SIM_DATA_DIR", legacyRoot.string());
    setEnvironment("HSM_SIM_PIN", "");
    EXPECT(C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = 0;
    CK_ULONG count = 1;
    EXPECT(C_GetSlotList(CK_TRUE, &slot, &count), CKR_OK);
    CHECK(slot == 1 && count == 1);
    auto session = open(1);
    aes(session, "legacy"); // No login required in the unchanged historical layout.
    CK_TOKEN_INFO info{};
    EXPECT(C_GetTokenInfo(1, &info), CKR_OK);
    CHECK(!(info.flags & CKF_LOGIN_REQUIRED));
    EXPECT(C_Finalize(nullptr), CKR_OK);
    writeText(legacyRoot / "so-pin.txt", "administrator");
    EXPECT(C_Initialize(nullptr), CKR_OK);
    session = open(1);
    EXPECT(C_GetTokenInfo(1, &info), CKR_OK);
    CHECK(info.flags & CKF_LOGIN_REQUIRED);
    CHECK(!(info.flags & CKF_USER_PIN_INITIALIZED));
    EXPECT(login(session, "anything"), CKR_USER_PIN_NOT_INITIALIZED);
    EXPECT(login(session, "administrator", CKU_SO), CKR_OK);
    EXPECT(initPin(session, "legacy-user"), CKR_OK);
    EXPECT(C_Logout(session), CKR_OK);
    EXPECT(login(session, "legacy-user"), CKR_OK);
    CHECK(findKey(session, "legacy", CKO_SECRET_KEY) != 0);
    EXPECT(C_Finalize(nullptr), CKR_OK);
    setEnvironment("HSM_SIM_DATA_DIR", root.string());
}

int main()
{
    try
    {
        const char* environment = std::getenv("HSM_SIM_DATA_DIR");
        CHECK(environment && *environment);
        const fs::path root(environment);
        CHECK(fs::is_empty(root));
        testSlots(root);
        testInvalidLayouts(root);
        testFallbackAndLegacy(root);
        std::cout << checks << " multi-slot and PIN checks passed\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
