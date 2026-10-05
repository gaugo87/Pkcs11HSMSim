#pragma once

#include "core/runtime.hpp"

namespace hsm
{

// Attribute reads and atomic updates of labels, IDs and usage policies.
CK_RV readAttributes(Object* object, CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount);
CK_RV GetAttributeValue(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE objectHandle,
    CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount);
CK_RV SetAttributeValue(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE handle,
    CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount);

} // namespace hsm
