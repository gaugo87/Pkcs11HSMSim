#include "crypto/derivation.hpp"
#include "core/openssl.hpp"
#include "core/runtime.hpp"
#include "core/utilities.hpp"
#include "objects/policy.hpp"
#include "objects/template.hpp"
#include "storage/key_store.hpp"
#include <cstring>
#include <limits>

namespace hsm
{

CK_RV DeriveKey(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism,
    CK_OBJECT_HANDLE baseKey, CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount,
    CK_OBJECT_HANDLE_PTR keyHandle)
{
    auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!mechanism || !keyHandle || (!attributes && attributeCount))
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (mechanism->mechanism != CKM_AES_ECB_ENCRYPT_DATA)
    {
        return CKR_MECHANISM_INVALID;
    }
    if (!mechanism->pParameter ||
        mechanism->ulParameterLen != sizeof(CK_KEY_DERIVATION_STRING_DATA))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    CK_KEY_DERIVATION_STRING_DATA data;
    std::memcpy(&data, mechanism->pParameter, sizeof data);
    if (!data.pData)
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    if (!data.ulLen || data.ulLen % 16 ||
        data.ulLen > static_cast<CK_ULONG>(std::numeric_limits<int>::max() - 16))
    {
        return CKR_DATA_LEN_RANGE;
    }
    auto* master = findObject(baseKey);
    if (!master)
    {
        return CKR_KEY_HANDLE_INVALID;
    }
    if (!policyValue(*master, CKA_DERIVE))
    {
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }
    if (master->objectClass != CKO_SECRET_KEY || master->keyType != CKK_AES)
    {
        return CKR_KEY_TYPE_INCONSISTENT;
    }
    if (master->secretValue.size() != 16 && master->secretValue.size() != 24 &&
        master->secretValue.size() != 32)
    {
        return CKR_KEY_SIZE_RANGE;
    }
    CK_BBOOL token = CK_FALSE;
    for (CK_ULONG i = 0; i < attributeCount; ++i)
    {
        auto& attribute = attributes[i];
        for (CK_ULONG j = 0; j < i; ++j)
        {
            if (attributes[j].type == attribute.type)
            {
                return CKR_TEMPLATE_INCONSISTENT;
            }
        }
        if (!attribute.pValue && attribute.ulValueLen)
        {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        switch (attribute.type)
        {
            case CKA_CLASS:
            case CKA_KEY_TYPE:
            case CKA_VALUE_LEN:
                if (!attribute.pValue || attribute.ulValueLen != sizeof(CK_ULONG))
                {
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                break;
            case CKA_MODIFIABLE:
            case CKA_DESTROYABLE:
            case CKA_TOKEN:
            case CKA_PRIVATE:
            case CKA_DERIVE:
            case CKA_WRAP:
            case CKA_UNWRAP:
            case CKA_ENCRYPT:
            case CKA_DECRYPT:
            case CKA_SIGN:
            case CKA_VERIFY:
            case CKA_SENSITIVE:
            case CKA_EXTRACTABLE:
            {
                if (!attribute.pValue || attribute.ulValueLen != sizeof(CK_BBOOL))
                {
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                auto value = *static_cast<CK_BBOOL*>(attribute.pValue);
                if (value != CK_TRUE && value != CK_FALSE)
                {
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                if (attribute.type == CKA_TOKEN)
                {
                    token = value;
                }
                break;
            }
            case CKA_LABEL:
            case CKA_ID:
                break;
            case CKA_VALUE:
                return CKR_TEMPLATE_INCONSISTENT;
            default:
                return CKR_ATTRIBUTE_TYPE_INVALID;
        }
    }
    if (templateUnsigned(attributes, attributeCount, CKA_CLASS).value_or(CKO_SECRET_KEY) !=
        CKO_SECRET_KEY)
    {
        return CKR_TEMPLATE_INCONSISTENT;
    }
    auto requestedType = templateUnsigned(attributes, attributeCount, CKA_KEY_TYPE),
         requestedLength = templateUnsigned(attributes, attributeCount, CKA_VALUE_LEN);
    // Generic-secret derivation is outside this simulator's AES storage model.
    if (!requestedType || !requestedLength)
    {
        return CKR_TEMPLATE_INCOMPLETE;
    }
    if (*requestedType != CKK_AES)
    {
        return CKR_TEMPLATE_INCONSISTENT;
    }
    if (*requestedLength != 16 && *requestedLength != 24 && *requestedLength != 32)
    {
        return CKR_KEY_SIZE_RANGE;
    }
    if (*requestedLength > data.ulLen)
    {
        return CKR_DATA_LEN_RANGE;
    }
    if (token && !(session->flags & CKF_RW_SESSION))
    {
        return CKR_SESSION_READ_ONLY;
    }
    std::string cipher = "AES-" + std::to_string(master->secretValue.size() * 8) + "-ECB";
    OpenSslPtr<EVP_CIPHER, EVP_CIPHER_free> cipherAlgorithm(
        EVP_CIPHER_fetch(nullptr, cipher.c_str(), nullptr), EVP_CIPHER_free);
    OpenSslPtr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> context(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!cipherAlgorithm || !context)
    {
        return CKR_DEVICE_ERROR;
    }
    if (EVP_EncryptInit_ex2(context.get(), cipherAlgorithm.get(), master->secretValue.data(),
            nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_set_padding(context.get(), 0) != 1)
    {
        return CKR_DEVICE_ERROR;
    }
    // Only leading blocks contribute to the requested key; ECB blocks are independent.
    size_t used = ((*requestedLength + 15) / 16) * 16;
    std::vector<unsigned char> value(used + 16);
    int written = 0, tail = 0;
    if (EVP_EncryptUpdate(context.get(), value.data(), &written, data.pData, (int)used) != 1 ||
        EVP_EncryptFinal_ex(context.get(), value.data() + written, &tail) != 1)
    {
        return CKR_DEVICE_ERROR;
    }
    if (written + tail != (int)used)
    {
        return CKR_DEVICE_ERROR;
    }
    value.resize(*requestedLength);
    Object object;
    object.handle = runtime.nextObjectHandle++;
    object.objectClass = CKO_SECRET_KEY;
    object.keyType = CKK_AES;
    object.label = templateString(
        attributes, attributeCount, CKA_LABEL, "derived-" + std::to_string(object.handle));
    object.id = templateString(attributes, attributeCount, CKA_ID, std::to_string(object.handle));
    object.secretValue = std::move(value);
    object.ownerSession = token ? 0 : sessionHandle;
    applyPolicyTemplate(object, attributes, attributeCount);
    if (token)
    {
        object.path =
            (runtime.storageRoot / "symmetric" / (safeFilename(object.label) + ".key")).string();
        auto result = saveSecretKey(object);
        if (result)
        {
            return result;
        }
    }
    auto handle = object.handle;
    runtime.objects.emplace(handle, std::move(object));
    if (token)
    {
        auto result = persistMetadata(runtime.objects.at(handle).path);
        if (result)
        {
            return result;
        }
    }
    *keyHandle = handle;
    return CKR_OK;
}

} // namespace hsm
