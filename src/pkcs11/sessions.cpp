#include "pkcs11/sessions.hpp"
#include "core/runtime.hpp"
#include "core/utilities.hpp"

namespace hsm
{

CK_RV OpenSession(
    CK_SLOT_ID slotId, CK_FLAGS flags, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR sessionHandle)
{
    if (initializationStatus())
    {
        return initializationStatus();
    }
    if (slotId != virtualSlotId)
    {
        return CKR_SLOT_ID_INVALID;
    }
    if (!sessionHandle || !(flags & CKF_SERIAL_SESSION))
    {
        return CKR_ARGUMENTS_BAD;
    }
    Session session{runtime.nextSessionHandle++, flags};
    *sessionHandle = session.handle;
    runtime.sessions.emplace(session.handle, std::move(session));
    return CKR_OK;
}

CK_RV CloseSession(CK_SESSION_HANDLE sessionHandle)
{
    if (!runtime.sessions.erase(sessionHandle))
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    for (auto it = runtime.objects.begin(); it != runtime.objects.end();)
    {
        if (it->second.ownerSession == sessionHandle)
        {
            it = runtime.objects.erase(it);
        }
        else
        {
            ++it;
        }
    }
    return CKR_OK;
}

CK_RV CloseAllSessions(CK_SLOT_ID slotId)
{
    if (slotId != virtualSlotId)
    {
        return CKR_SLOT_ID_INVALID;
    }

    runtime.sessions.clear();
    for (auto it = runtime.objects.begin(); it != runtime.objects.end();)
    {
        if (it->second.ownerSession)
        {
            it = runtime.objects.erase(it);
        }
        else
        {
            ++it;
        }
    }
    return CKR_OK;
}

CK_RV GetSessionInfo(CK_SESSION_HANDLE sessionHandle, CK_SESSION_INFO_PTR info)
{
    auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!info)
    {
        return CKR_ARGUMENTS_BAD;
    }
    info->slotID = virtualSlotId;
    info->flags = session->flags;
    info->state = session->loggedIn
        ? ((session->flags & CKF_RW_SESSION) ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS)
        : ((session->flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION);
    info->ulDeviceError = 0;
    return CKR_OK;
}

CK_RV Login(
    CK_SESSION_HANDLE sessionHandle, CK_USER_TYPE userType, CK_CHAR_PTR pin, CK_ULONG pinLength)
{
    auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (userType != CKU_USER && userType != CKU_SO)
    {
        return CKR_USER_TYPE_INVALID;
    }
    if (session->loggedIn)
    {
        return CKR_USER_ALREADY_LOGGED_IN;
    }
    std::string expected = environmentValue("HSM_SIM_PIN", "");
    if (!expected.empty() && (!pin || std::string(pin, pin + pinLength) != expected))
    {
        return CKR_PIN_INCORRECT;
    }
    session->loggedIn = true;
    return CKR_OK;
}

CK_RV Logout(CK_SESSION_HANDLE sessionHandle)
{
    auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!session->loggedIn)
    {
        return CKR_USER_NOT_LOGGED_IN;
    }
    session->loggedIn = false;
    return CKR_OK;
}

} // namespace hsm
