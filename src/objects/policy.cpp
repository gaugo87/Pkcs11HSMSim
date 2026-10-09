#include "objects/policy.hpp"
#include "objects/template.hpp"
#include <cstring>

namespace hsm
{

bool isPolicyAttribute(CK_ATTRIBUTE_TYPE attributeType)
{
    switch (attributeType)
    {
        case CKA_SIGN:
        case CKA_VERIFY:
        case CKA_WRAP:
        case CKA_UNWRAP:
        case CKA_DERIVE:
        case CKA_ENCRYPT:
        case CKA_DECRYPT:
        case CKA_EXTRACTABLE:
        case CKA_SENSITIVE:
        case CKA_PRIVATE:
        case CKA_MODIFIABLE:
        case CKA_DESTROYABLE:
            return true;
        default:
            return false;
    }
}

bool policyValue(const Object& object, CK_ATTRIBUTE_TYPE attributeType)
{
    auto it = object.policy.find(static_cast<std::uint32_t>(attributeType));
    if (it != object.policy.end())
    {
        return it->second;
    }
    switch (attributeType)
    {
        case CKA_SIGN:
        case CKA_PRIVATE:
            return object.objectClass == CKO_PRIVATE_KEY;
        case CKA_VERIFY:
            return object.objectClass == CKO_PUBLIC_KEY;
        case CKA_WRAP:
        case CKA_UNWRAP:
        case CKA_DERIVE:
        case CKA_ENCRYPT:
        case CKA_DECRYPT:
            return object.objectClass == CKO_SECRET_KEY && object.keyType == CKK_AES;
        case CKA_SENSITIVE:
            return false;
        case CKA_EXTRACTABLE:
        case CKA_MODIFIABLE:
        case CKA_DESTROYABLE:
            return true;
        default:
            return false;
    }
}

CK_RV validateCreationTemplate(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount)
{
    if (!attributes && attributeCount)
    {
        return CKR_ARGUMENTS_BAD;
    }
    for (CK_ULONG i = 0; i < attributeCount; ++i)
    {
        for (CK_ULONG j = 0; j < i; ++j)
        {
            if (attributes[i].type == attributes[j].type)
            {
                return CKR_TEMPLATE_INCONSISTENT;
            }
        }
        if (!attributes[i].pValue && attributes[i].ulValueLen)
        {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (isPolicyAttribute(attributes[i].type) || attributes[i].type == CKA_TOKEN)
        {
            if (!attributes[i].pValue || attributes[i].ulValueLen != sizeof(CK_BBOOL))
            {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            CK_BBOOL value;
            std::memcpy(&value, attributes[i].pValue, sizeof value);
            if (value != CK_FALSE && value != CK_TRUE)
            {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
        }
        else
        {
            switch (attributes[i].type)
            {
                case CKA_CLASS:
                case CKA_KEY_TYPE:
                case CKA_VALUE_LEN:
                case CKA_MODULUS_BITS:
                case CKA_PARAMETER_SET:
                    if (!attributes[i].pValue || attributes[i].ulValueLen != sizeof(CK_ULONG))
                    {
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    break;
                case CKA_LABEL:
                case CKA_ID:
                case CKA_EC_PARAMS:
                case CKA_PUBLIC_EXPONENT:
                    break;
                case CKA_ALWAYS_SENSITIVE:
                case CKA_NEVER_EXTRACTABLE:
                case CKA_LOCAL:
                case CKA_KEY_GEN_MECHANISM:
                    return CKR_ATTRIBUTE_READ_ONLY;
                case CKA_VALUE:
                    return CKR_TEMPLATE_INCONSISTENT;
                default:
                    return CKR_ATTRIBUTE_TYPE_INVALID;
            }
        }
    }
    return CKR_OK;
}

bool isTokenTemplate(CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, bool fallback)
{
    auto value = templateBytes(attributes, attributeCount, CKA_TOKEN);
    return value ? (*value)[0] != 0 : fallback;
}

void applyPolicyTemplate(Object& object, CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount)
{
    for (CK_ULONG i = 0; i < attributeCount; ++i)
    {
        if (isPolicyAttribute(attributes[i].type))
        {
            object.policy[static_cast<std::uint32_t>(attributes[i].type)] =
                *static_cast<CK_BBOOL*>(attributes[i].pValue) != 0;
        }
    }
}

CK_RV applyCreationTemplate(Object& object, CK_SESSION_HANDLE sessionHandle,
    CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, bool fallback)
{
    auto result = validateCreationTemplate(attributes, attributeCount);
    if (result)
    {
        return result;
    }
    if (templateUnsigned(attributes, attributeCount, CKA_CLASS).value_or(object.objectClass) !=
            object.objectClass ||
        templateUnsigned(attributes, attributeCount, CKA_KEY_TYPE).value_or(object.keyType) !=
            object.keyType)
    {
        return CKR_TEMPLATE_INCONSISTENT;
    }
    bool token = isTokenTemplate(attributes, attributeCount, fallback);
    if (token && !(findSession(sessionHandle)->flags & CKF_RW_SESSION))
    {
        return CKR_SESSION_READ_ONLY;
    }
    if (auto access = requireUserLogin(sessionHandle); access != CKR_OK)
    {
        return access;
    }
    object.slotId = findSession(sessionHandle)->slotId;
    object.ownerSession = token ? 0 : sessionHandle;
    applyPolicyTemplate(object, attributes, attributeCount);
    if (object.ownerSession)
    {
        object.path.clear();
    }
    return CKR_OK;
}

} // namespace hsm
