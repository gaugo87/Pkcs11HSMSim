#pragma once

#include "pkcs11.h"

namespace hsm
{

// Session lifecycle and simplified login state.
CK_RV OpenSession(
    CK_SLOT_ID slotId, CK_FLAGS flags, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR sessionHandle);
CK_RV CloseSession(CK_SESSION_HANDLE sessionHandle);
CK_RV CloseAllSessions(CK_SLOT_ID slotId);
CK_RV GetSessionInfo(CK_SESSION_HANDLE sessionHandle, CK_SESSION_INFO_PTR info);
CK_RV Login(
    CK_SESSION_HANDLE sessionHandle, CK_USER_TYPE userType, CK_CHAR_PTR pin, CK_ULONG pinLength);
CK_RV Logout(CK_SESSION_HANDLE sessionHandle);

} // namespace hsm
