#include "objects/attributes.hpp"
#include "core/openssl.hpp"
#include "crypto/mechanisms.hpp"
#include "objects/policy.hpp"
#include "objects/template.hpp"
#include "storage/key_store.hpp"
#include <cstring>
#include <openssl/core_names.h>
#include <openssl/x509.h>

namespace hsm
{

static CK_RV writeAttribute(CK_ATTRIBUTE& attribute, const void* value, size_t length)
{
    if (!attribute.pValue)
    {
        attribute.ulValueLen = length;
        return CKR_OK;
    }
    if (attribute.ulValueLen < length)
    {
        attribute.ulValueLen = length;
        return CKR_BUFFER_TOO_SMALL;
    }
    std::memcpy(attribute.pValue, value, length);
    attribute.ulValueLen = length;
    return CKR_OK;
}

static CK_RV readRsaAttribute(const Object& object, CK_ATTRIBUTE& attribute)
{
    CK_RV attributeResult = CKR_OK;
    BIGNUM* bn = nullptr;
    if (!object.asymmetricKey || object.keyType != CKK_RSA ||
        EVP_PKEY_get_bn_param(object.asymmetricKey.get(),
            attribute.type == CKA_MODULUS ? OSSL_PKEY_PARAM_RSA_N : OSSL_PKEY_PARAM_RSA_E,
            &bn) != 1)
    {
        attributeResult = CKR_ATTRIBUTE_TYPE_INVALID;
        attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION;
        return attributeResult;
    }
    OpenSslPtr<BIGNUM, BN_free> number(bn, BN_free);
    std::vector<unsigned char> bytes(BN_num_bytes(bn));
    BN_bn2bin(bn, bytes.data());
    attributeResult = writeAttribute(attribute, bytes.data(), bytes.size());
    return attributeResult;
}

static CK_RV readEcAttribute(const Object& object, CK_ATTRIBUTE& attribute)
{
    CK_RV attributeResult = CKR_OK;
    if (!object.asymmetricKey || object.keyType != CKK_EC)
    {
        attributeResult = CKR_ATTRIBUTE_TYPE_INVALID;
        attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION;
        return attributeResult;
    }
    std::vector<unsigned char> bytes;
    if (attribute.type == CKA_EC_PARAMS)
    {
        char group[128];
        size_t size = 0;
        if (EVP_PKEY_get_utf8_string_param(object.asymmetricKey.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                group, sizeof group, &size) != 1)
        {
            attributeResult = CKR_DEVICE_ERROR;
            return attributeResult;
        }
        const ASN1_OBJECT* oid = OBJ_nid2obj(OBJ_txt2nid(group));
        int derLength = oid ? i2d_ASN1_OBJECT(oid, nullptr) : 0;
        if (derLength <= 0)
        {
            attributeResult = CKR_DEVICE_ERROR;
            return attributeResult;
        }
        bytes.resize(derLength);
        auto cursor = bytes.data();
        i2d_ASN1_OBJECT(oid, &cursor);
    }
    else
    {
        size_t size = 0;
        if (EVP_PKEY_get_octet_string_param(
                object.asymmetricKey.get(), OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &size) != 1)
        {
            attributeResult = CKR_DEVICE_ERROR;
            return attributeResult;
        }
        std::vector<unsigned char> raw(size);
        if (EVP_PKEY_get_octet_string_param(object.asymmetricKey.get(), OSSL_PKEY_PARAM_PUB_KEY,
                raw.data(), raw.size(), &size) != 1)
        {
            attributeResult = CKR_DEVICE_ERROR;
            return attributeResult;
        }
        OpenSslPtr<ASN1_OCTET_STRING, ASN1_OCTET_STRING_free> oct(
            ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free);
        if (!oct || ASN1_OCTET_STRING_set(oct.get(), raw.data(), (int)size) != 1)
        {
            attributeResult = CKR_DEVICE_ERROR;
            return attributeResult;
        }
        int derLength = i2d_ASN1_OCTET_STRING(oct.get(), nullptr);
        bytes.resize(derLength);
        auto cursor = bytes.data();
        i2d_ASN1_OCTET_STRING(oct.get(), &cursor);
    }
    attributeResult = writeAttribute(attribute, bytes.data(), bytes.size());
    return attributeResult;
}

CK_RV readAttributes(Object* object, CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount)
{
    if (!attributes && attributeCount)
    {
        return CKR_ARGUMENTS_BAD;
    }
    CK_RV result = CKR_OK;
    for (CK_ULONG i = 0; i < attributeCount; i++)
    {
        CK_RV attributeResult = CKR_OK;
        switch (attributes[i].type)
        {
            case CKA_MODIFIABLE:
            case CKA_DESTROYABLE:
            case CKA_ENCRYPT:
            case CKA_DECRYPT:
            case CKA_DERIVE:
            case CKA_TOKEN:
            case CKA_PRIVATE:
            case CKA_SIGN:
            case CKA_VERIFY:
            case CKA_WRAP:
            case CKA_UNWRAP:
            case CKA_EXTRACTABLE:
            case CKA_SENSITIVE:
            {
                CK_BBOOL value = attributes[i].type == CKA_TOKEN
                    ? !object->ownerSession
                    : policyValue(*object, attributes[i].type);
                attributeResult = writeAttribute(attributes[i], &value, sizeof value);
                break;
            }
            case CKA_VALUE_LEN:
            {
                CK_ULONG value = object->secretValue.size();
                attributeResult = writeAttribute(attributes[i], &value, sizeof value);
                break;
            }
            case CKA_MODULUS_BITS:
            {
                if (!object->asymmetricKey || object->keyType != CKK_RSA)
                {
                    attributeResult = CKR_ATTRIBUTE_TYPE_INVALID;
                    attributes[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    break;
                }
                CK_ULONG value = EVP_PKEY_get_bits(object->asymmetricKey.get());
                attributeResult = writeAttribute(attributes[i], &value, sizeof value);
                break;
            }
            case CKA_MODULUS:
            case CKA_PUBLIC_EXPONENT:
                attributeResult = readRsaAttribute(*object, attributes[i]);
                break;
            case CKA_EC_PARAMS:
            case CKA_EC_POINT:
                attributeResult = readEcAttribute(*object, attributes[i]);
                break;
            case CKA_CLASS:
                attributeResult =
                    writeAttribute(attributes[i], &object->objectClass, sizeof object->objectClass);
                break;
            case CKA_KEY_TYPE:
                attributeResult =
                    writeAttribute(attributes[i], &object->keyType, sizeof object->keyType);
                break;
            case CKA_LABEL:
                attributeResult =
                    writeAttribute(attributes[i], object->label.data(), object->label.size());
                break;
            case CKA_ID:
                attributeResult =
                    writeAttribute(attributes[i], object->id.data(), object->id.size());
                break;
            case CKA_PARAMETER_SET:
            {
                auto ps = keyParameterSet(*object);
                if (!ps)
                {
                    attributeResult = CKR_ATTRIBUTE_TYPE_INVALID;
                    attributes[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                }
                else
                {
                    attributeResult = writeAttribute(attributes[i], &ps, sizeof ps);
                }
                break;
            }
            case CKA_VALUE:
                if (object->objectClass == CKO_SECRET_KEY)
                {
                    if (policyValue(*object, CKA_SENSITIVE) ||
                        !policyValue(*object, CKA_EXTRACTABLE))
                    {
                        attributeResult = CKR_ATTRIBUTE_SENSITIVE;
                        attributes[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    }
                    else
                    {
                        attributeResult = writeAttribute(
                            attributes[i], object->secretValue.data(), object->secretValue.size());
                    }
                }
                else if (object->objectClass == CKO_CERTIFICATE)
                {
                    attributeResult = writeAttribute(attributes[i], object->certificateDer.data(),
                        object->certificateDer.size());
                }
                else
                {
                    attributeResult = CKR_ATTRIBUTE_TYPE_INVALID;
                    attributes[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                }
                break;
            default:
                attributeResult = CKR_ATTRIBUTE_TYPE_INVALID;
                attributes[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
        }
        if (attributeResult != CKR_OK)
        {
            result = attributeResult;
        }
    }
    return result;
}

CK_RV GetAttributeValue(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE objectHandle,
    CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount)
{
    if (!findSession(sessionHandle))
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    auto* object = findObject(sessionHandle, objectHandle);
    if (!object)
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    if (auto access = objectAccessStatus(sessionHandle, *object); access != CKR_OK)
    {
        return access;
    }
    return readAttributes(object, attributes, attributeCount);
}

CK_RV SetAttributeValue(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE handle,
    CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount)
{
    if (!findSession(sessionHandle))
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    auto* object = findObject(sessionHandle, handle);
    if (!object)
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    if (auto access = requireUserLogin(sessionHandle); access != CKR_OK)
    {
        return access;
    }
    if (!policyValue(*object, CKA_MODIFIABLE))
    {
        return CKR_ACTION_PROHIBITED;
    }
    if (!object->ownerSession && !(findSession(sessionHandle)->flags & CKF_RW_SESSION))
    {
        return CKR_SESSION_READ_ONLY;
    }
    auto result = validateCreationTemplate(attributes, attributeCount);
    if (result)
    {
        return result;
    }
    Object changed = *object;
    for (CK_ULONG i = 0; i < attributeCount; ++i)
    {
        auto attributeType = attributes[i].type;
        if (attributeType == CKA_LABEL || attributeType == CKA_ID)
        {
            auto value = templateString(attributes + i, 1, attributeType);
            if (attributeType == CKA_LABEL)
            {
                changed.label = value;
            }
            else
            {
                changed.id = value;
            }
        }
        else if (isPolicyAttribute(attributeType))
        {
            bool value = *static_cast<CK_BBOOL*>(attributes[i].pValue) != 0;
            if ((attributeType == CKA_SENSITIVE && policyValue(*object, attributeType) && !value) ||
                (attributeType == CKA_EXTRACTABLE && !policyValue(*object, attributeType) && value))
            {
                return CKR_ATTRIBUTE_READ_ONLY;
            }
            changed.policy[static_cast<std::uint32_t>(attributeType)] = value;
        }
        else
        {
            return CKR_ATTRIBUTE_READ_ONLY;
        }
    }
    if (!changed.ownerSession)
    {
        try
        {
            metadata::create(changed.path, collectMetadata(changed.path, &changed), true);
        }
        catch (...)
        {
            return CKR_DEVICE_ERROR;
        }
    }
    *object = std::move(changed);
    return CKR_OK;
}

} // namespace hsm
