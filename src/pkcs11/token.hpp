#pragma once

#include "pkcs11.h"

namespace hsm
{

// Library lifecycle and virtual slot/token information.
CK_RV Initialize(CK_VOID_PTR arguments);
CK_RV Finalize(CK_VOID_PTR reserved);
CK_RV GetInfo(CK_INFO_PTR info);
CK_RV GetSlotList(CK_BBOOL, CK_SLOT_ID_PTR slots, CK_ULONG_PTR count);
CK_RV GetSlotInfo(CK_SLOT_ID slotId, CK_SLOT_INFO_PTR info);
CK_RV GetTokenInfo(CK_SLOT_ID slotId, CK_TOKEN_INFO_PTR info);
CK_RV GetMechanismList(CK_SLOT_ID slotId, CK_MECHANISM_TYPE_PTR mechanisms, CK_ULONG_PTR count);
CK_RV GetMechanismInfo(CK_SLOT_ID slotId, CK_MECHANISM_TYPE mechanism, CK_MECHANISM_INFO_PTR info);

} // namespace hsm
