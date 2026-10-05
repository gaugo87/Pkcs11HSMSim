#include "objects/template.hpp"
#include <cstring>

namespace hsm
{

std::optional<std::vector<unsigned char>> templateBytes(
    CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE attributeType)
{
    if (!attributes)
    {
        return {};
    }
    for (CK_ULONG i = 0; i < attributeCount; i++)
    {
        if (attributes[i].type == attributeType)
        {
            if (attributes[i].ulValueLen == 0)
            {
                return std::vector<unsigned char>{};
            }
            if (!attributes[i].pValue)
            {
                return {};
            }
            return std::vector<unsigned char>((unsigned char*)attributes[i].pValue,
                (unsigned char*)attributes[i].pValue + attributes[i].ulValueLen);
        }
    }
    return {};
}

std::string templateString(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount,
    CK_ATTRIBUTE_TYPE attributeType, const std::string& fallback)
{
    auto value = templateBytes(attributes, attributeCount, attributeType);
    return value ? std::string(value->begin(), value->end()) : fallback;
}

std::optional<CK_ULONG> templateUnsigned(
    CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_ATTRIBUTE_TYPE attributeType)
{
    auto value = templateBytes(attributes, attributeCount, attributeType);
    if (!value || value->size() != sizeof(CK_ULONG))
    {
        return {};
    }
    CK_ULONG number;
    std::memcpy(&number, value->data(), sizeof number);
    return number;
}

} // namespace hsm
