#include "core/runtime.hpp"
#include "objects/policy.hpp"

namespace hsm
{

RuntimeState runtime;

CK_RV initializationStatus()
{
    return runtime.initialized ? CKR_OK : CKR_CRYPTOKI_NOT_INITIALIZED;
}

Session* findSession(CK_SESSION_HANDLE handle)
{
    auto entry = runtime.sessions.find(handle);
    return entry == runtime.sessions.end() ? nullptr : &entry->second;
}

Slot* findSlot(CK_SLOT_ID slotId)
{
    auto entry = runtime.slots.find(slotId);
    return entry == runtime.slots.end() ? nullptr : &entry->second;
}

Slot& sessionSlot(CK_SESSION_HANDLE sessionHandle)
{
    return runtime.slots.at(runtime.sessions.at(sessionHandle).slotId);
}

Object* findObject(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE handle)
{
    const auto* session = findSession(sessionHandle);
    auto entry = runtime.objects.find(handle);
    return session && entry != runtime.objects.end() && entry->second.slotId == session->slotId
        ? &entry->second
        : nullptr;
}

bool isProtectedObject(const Object& object)
{
    // A configured slot PIN protects key material even when CKA_PRIVATE is false.
    return object.objectClass == CKO_PRIVATE_KEY || object.objectClass == CKO_SECRET_KEY ||
        policyValue(object, CKA_PRIVATE);
}

CK_RV requireUserLogin(CK_SESSION_HANDLE sessionHandle)
{
    const auto& slot = sessionSlot(sessionHandle);
    return !slot.requiresLogin() || slot.loggedInUser == CKU_USER ? CKR_OK : CKR_USER_NOT_LOGGED_IN;
}

CK_RV objectAccessStatus(CK_SESSION_HANDLE sessionHandle, const Object& object)
{
    return isProtectedObject(object) ? requireUserLogin(sessionHandle) : CKR_OK;
}

} // namespace hsm
