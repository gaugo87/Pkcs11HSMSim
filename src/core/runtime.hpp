#pragma once

#include "pkcs11.h"
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <openssl/evp.h>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace hsm
{

namespace fs = std::filesystem;

// A slot is discovered once at C_Initialize. Login belongs to its token, not a session.
struct Slot
{
    CK_SLOT_ID id{};
    std::string label;
    fs::path directory;
    std::optional<std::string> userPin;
    std::optional<std::string> soPin;
    std::string p12Password;
    bool legacyLayout = false;
    std::optional<CK_USER_TYPE> loggedInUser;

    bool requiresLogin() const
    {
        return !legacyLayout || userPin.has_value() || soPin.has_value();
    }
};

struct Object
{
    CK_OBJECT_HANDLE handle{};
    CK_SLOT_ID slotId{};
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
    CK_SLOT_ID slotId{};
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
    std::map<CK_SLOT_ID, Slot> slots;
    std::unordered_map<CK_OBJECT_HANDLE, Object> objects;
    std::unordered_map<CK_SESSION_HANDLE, Session> sessions;
    std::mutex mutex;
};

// One registry per loaded module. Internal functions require its lock.
extern RuntimeState runtime;

// In-memory token state. Access is serialized by the PKCS#11 entry-point boundary.
CK_RV initializationStatus();
Session* findSession(CK_SESSION_HANDLE handle);
Slot* findSlot(CK_SLOT_ID slotId);
Slot& sessionSlot(CK_SESSION_HANDLE sessionHandle);
Object* findObject(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE handle);
bool isProtectedObject(const Object& object);
CK_RV requireUserLogin(CK_SESSION_HANDLE sessionHandle);
CK_RV objectAccessStatus(CK_SESSION_HANDLE sessionHandle, const Object& object);

} // namespace hsm
