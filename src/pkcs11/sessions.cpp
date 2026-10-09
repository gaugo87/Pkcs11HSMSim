#include "pkcs11/sessions.hpp"
#include "core/runtime.hpp"
#include "storage/slots.hpp"
#include <algorithm>

namespace hsm
{

CK_RV OpenSession(
    CK_SLOT_ID slotId, CK_FLAGS flags, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR sessionHandle)
{
    auto* slot = findSlot(slotId);
    if (!slot)
    {
        return CKR_SLOT_ID_INVALID;
    }
    if (!sessionHandle)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (!(flags & CKF_SERIAL_SESSION))
    {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }
    if (!(flags & CKF_RW_SESSION) && slot->loggedInUser == CKU_SO)
    {
        return CKR_SESSION_READ_WRITE_SO_EXISTS;
    }
    Session session;
    session.handle = runtime.nextSessionHandle++;
    session.slotId = slotId;
    session.flags = flags;
    const auto handle = session.handle;
    runtime.sessions.emplace(handle, std::move(session));
    *sessionHandle = handle;
    return CKR_OK;
}

CK_RV CloseSession(CK_SESSION_HANDLE sessionHandle)
{
    auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    const auto slotId = session->slotId;
    runtime.sessions.erase(sessionHandle);
    std::erase_if(runtime.objects,
        [sessionHandle](const auto& entry)
        {
            return entry.second.ownerSession == sessionHandle;
        });
    if (std::none_of(runtime.sessions.begin(), runtime.sessions.end(),
            [slotId](const auto& entry)
            {
                return entry.second.slotId == slotId;
            }))
    {
        runtime.slots.at(slotId).loggedInUser.reset();
    }
    return CKR_OK;
}

CK_RV CloseAllSessions(CK_SLOT_ID slotId)
{
    auto* slot = findSlot(slotId);
    if (!slot)
    {
        return CKR_SLOT_ID_INVALID;
    }
    std::erase_if(runtime.sessions,
        [slotId](const auto& entry)
        {
            return entry.second.slotId == slotId;
        });
    std::erase_if(runtime.objects,
        [slotId](const auto& entry)
        {
            return entry.second.slotId == slotId && entry.second.ownerSession != 0;
        });
    slot->loggedInUser.reset();
    return CKR_OK;
}

CK_RV GetSessionInfo(CK_SESSION_HANDLE sessionHandle, CK_SESSION_INFO_PTR info)
{
    const auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!info)
    {
        return CKR_ARGUMENTS_BAD;
    }
    const auto& slot = sessionSlot(sessionHandle);
    info->slotID = session->slotId;
    info->flags = session->flags;
    if (slot.loggedInUser == CKU_SO)
    {
        info->state = CKS_RW_SO_FUNCTIONS;
    }
    else if (slot.loggedInUser == CKU_USER)
    {
        info->state =
            (session->flags & CKF_RW_SESSION) ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
    }
    else
    {
        info->state =
            (session->flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
    }
    info->ulDeviceError = 0;
    return CKR_OK;
}

CK_RV Login(
    CK_SESSION_HANDLE sessionHandle, CK_USER_TYPE userType, CK_CHAR_PTR pin, CK_ULONG pinLength)
{
    const auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (userType != CKU_USER && userType != CKU_SO)
    {
        return CKR_USER_TYPE_INVALID;
    }
    if (!pin && pinLength)
    {
        return CKR_ARGUMENTS_BAD;
    }
    auto& slot = sessionSlot(sessionHandle);
    if (slot.loggedInUser)
    {
        return *slot.loggedInUser == userType ? CKR_USER_ALREADY_LOGGED_IN
                                              : CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
    }
    if (userType == CKU_SO)
    {
        if (!(session->flags & CKF_RW_SESSION))
        {
            return CKR_SESSION_READ_ONLY;
        }
        if (std::any_of(runtime.sessions.begin(), runtime.sessions.end(),
                [&](const auto& entry)
                {
                    return entry.second.slotId == slot.id && !(entry.second.flags & CKF_RW_SESSION);
                }))
        {
            return CKR_SESSION_READ_ONLY_EXISTS;
        }
    }
    const auto& expected = userType == CKU_SO ? slot.soPin : slot.userPin;
    // The historical flat layout without a PIN remains permissive for existing clients.
    CK_RV result = slot.legacyLayout && !slot.requiresLogin() && !expected
        ? CKR_OK
        : checkPin(expected, pin, pinLength);
    if (result != CKR_OK)
    {
        return result;
    }
    slot.loggedInUser = userType;
    return CKR_OK;
}

CK_RV Logout(CK_SESSION_HANDLE sessionHandle)
{
    if (!findSession(sessionHandle))
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    auto& slot = sessionSlot(sessionHandle);
    if (!slot.loggedInUser)
    {
        return CKR_USER_NOT_LOGGED_IN;
    }
    slot.loggedInUser.reset();
    for (auto& [handle, session] : runtime.sessions)
    {
        if (session.slotId == slot.id)
        {
            session.operation = {};
            session.searchActive = false;
            session.matches.clear();
        }
    }
    std::erase_if(runtime.objects,
        [&](const auto& entry)
        {
            return entry.second.slotId == slot.id && entry.second.ownerSession &&
                isProtectedObject(entry.second);
        });
    return CKR_OK;
}

CK_RV InitPIN(CK_SESSION_HANDLE sessionHandle, CK_CHAR_PTR pin, CK_ULONG pinLength)
{
    const auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!(session->flags & CKF_RW_SESSION))
    {
        return CKR_SESSION_READ_ONLY;
    }
    auto& slot = sessionSlot(sessionHandle);
    if (slot.loggedInUser != CKU_SO)
    {
        return CKR_USER_NOT_LOGGED_IN;
    }
    return storePin(slot, CKU_USER, pin, pinLength);
}

CK_RV SetPIN(CK_SESSION_HANDLE sessionHandle, CK_CHAR_PTR oldPin, CK_ULONG oldLength,
    CK_CHAR_PTR newPin, CK_ULONG newLength)
{
    const auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!(session->flags & CKF_RW_SESSION))
    {
        return CKR_SESSION_READ_ONLY;
    }
    if ((!oldPin && oldLength) || (!newPin && newLength))
    {
        return CKR_ARGUMENTS_BAD;
    }
    auto& slot = sessionSlot(sessionHandle);
    const auto userType = slot.loggedInUser.value_or(CKU_USER);
    const auto& expected = userType == CKU_SO ? slot.soPin : slot.userPin;
    const auto result = slot.legacyLayout && !slot.requiresLogin() && !expected
        ? CKR_OK
        : checkPin(expected, oldPin, oldLength);
    if (result != CKR_OK)
    {
        return result;
    }
    return storePin(slot, userType, newPin, newLength);
}

} // namespace hsm
