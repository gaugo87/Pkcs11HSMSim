#pragma once

#include "core/runtime.hpp"

namespace hsm
{

inline constexpr CK_ULONG maximumPinLength = 256;

// Reads slotID_slotLabel directories, or the historical flat token directory.
// Discovery is transactional: the registry is published only after validation.
void discoverSlots();
CK_RV validatePin(CK_CHAR_PTR pin, CK_ULONG length);
CK_RV checkPin(const std::optional<std::string>& expected, CK_CHAR_PTR pin, CK_ULONG length);
CK_RV storePin(Slot& slot, CK_USER_TYPE userType, CK_CHAR_PTR pin, CK_ULONG length);

} // namespace hsm
