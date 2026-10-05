#pragma once

#include "pkcs11.h"
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <openssl/evp.h>
#include <string>
#include <unordered_map>
#include <vector>

namespace hsm
{

namespace fs = std::filesystem;

inline constexpr CK_SLOT_ID virtualSlotId = 1;

struct Object
{
    CK_OBJECT_HANDLE handle{};
    CK_OBJECT_CLASS objectClass{};
    CK_KEY_TYPE keyType{};
    std::string label;
    std::string id;
    std::string path;
    std::string algorithmName;
    std::vector<unsigned char> secretValue;
    std::vector<unsigned char> certificateDer;
    std::shared_ptr<EVP_PKEY> asymmetricKey;
    // Zero for a persistent token object; otherwise the creating session.
    CK_SESSION_HANDLE ownerSession{};
    std::map<std::uint32_t, bool> policy;
};

struct Operation
{
    bool active = false;
    bool verify = false;
    CK_MECHANISM_TYPE mechanism{};
    CK_OBJECT_HANDLE keyHandle{};
    std::vector<unsigned char> bufferedData;
    CK_RSA_PKCS_PSS_PARAMS pss{};
};

struct Session
{
    CK_SESSION_HANDLE handle{};
    CK_FLAGS flags{};
    bool loggedIn = false;
    bool searchActive = false;
    std::vector<CK_OBJECT_HANDLE> matches;
    size_t searchOffset = 0;
    Operation operation;
};

struct RuntimeState
{
    bool initialized = false;
    fs::path storageRoot;
    CK_OBJECT_HANDLE nextObjectHandle = 1;
    CK_SESSION_HANDLE nextSessionHandle = 1;
    std::unordered_map<CK_OBJECT_HANDLE, Object> objects;
    std::unordered_map<CK_SESSION_HANDLE, Session> sessions;
    std::mutex mutex;
};

// One virtual token per loaded module. Internal functions require its lock.
extern RuntimeState runtime;

// In-memory token state. Access is serialized by the PKCS#11 entry-point boundary.
CK_RV initializationStatus();
Session* findSession(CK_SESSION_HANDLE handle);
Object* findObject(CK_OBJECT_HANDLE handle);

} // namespace hsm
