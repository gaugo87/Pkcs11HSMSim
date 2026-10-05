#pragma once

#include "pkcs11.h"
#include <optional>
#include <string>
#include <vector>

namespace hsm
{

// Readers for caller-owned PKCS#11 attribute templates.
std::optional<std::vector<unsigned char>> templateBytes(
    CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE attributeType);
std::string templateString(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount,
    CK_ATTRIBUTE_TYPE attributeType, const std::string& fallback = "");
std::optional<CK_ULONG> templateUnsigned(
    CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE attributeType);

} // namespace hsm
