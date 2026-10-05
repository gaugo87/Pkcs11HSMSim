#pragma once

#include "core/runtime.hpp"

namespace hsm
{

// Attribute validation and usage policies, including defaults for legacy key files.
bool isPolicyAttribute(CK_ATTRIBUTE_TYPE attributeType);
bool policyValue(const Object& object, CK_ATTRIBUTE_TYPE attributeType);
CK_RV validateCreationTemplate(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount);
bool isTokenTemplate(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, bool fallback = true);
void applyPolicyTemplate(Object& object, CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount);
CK_RV applyCreationTemplate(Object& object, CK_SESSION_HANDLE sessionHandle,
    CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, bool fallback = true);

} // namespace hsm
