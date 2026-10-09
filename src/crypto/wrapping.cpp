#include "crypto/wrapping.hpp"
#include "core/openssl.hpp"
#include "core/runtime.hpp"
#include "core/utilities.hpp"
#include "crypto/mechanisms.hpp"
#include "objects/policy.hpp"
#include "objects/template.hpp"
#include "storage/key_store.hpp"
#include <limits>
#include <openssl/x509.h>

namespace hsm
{

static CK_RV aesKeyWrap(bool unwrap, CK_MECHANISM_PTR mechanism, Object* wrappingKey,
    const unsigned char* input, size_t inputLength, unsigned char* output, size_t* outputLength)
{
    if (!mechanism || !wrappingKey || wrappingKey->keyType != CKK_AES)
    {
        return CKR_KEY_TYPE_INCONSISTENT;
    }
    if (mechanism->mechanism != CKM_AES_KEY_WRAP && mechanism->mechanism != CKM_AES_KEY_WRAP_PAD)
    {
        return CKR_MECHANISM_INVALID;
    }
    if (mechanism->pParameter || mechanism->ulParameterLen)
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    if (inputLength > static_cast<size_t>(std::numeric_limits<int>::max()) - 16)
    {
        return CKR_DATA_LEN_RANGE;
    }
    if (wrappingKey->secretValue.size() != 16 && wrappingKey->secretValue.size() != 24 &&
        wrappingKey->secretValue.size() != 32)
    {
        return CKR_KEY_SIZE_RANGE;
    }
    if (mechanism->mechanism == CKM_AES_KEY_WRAP &&
        ((inputLength % 8) != 0 || inputLength < (unwrap ? 24 : 16)))
    {
        return CKR_DATA_LEN_RANGE;
    }
    if (mechanism->mechanism == CKM_AES_KEY_WRAP_PAD &&
        (inputLength == 0 || (unwrap && (inputLength < 16 || inputLength % 8))))
    {
        return CKR_DATA_LEN_RANGE;
    }
    std::string cipher = "AES-" + std::to_string(wrappingKey->secretValue.size() * 8) +
        (mechanism->mechanism == CKM_AES_KEY_WRAP ? "-WRAP" : "-WRAP-PAD");
    OpenSslPtr<EVP_CIPHER, EVP_CIPHER_free> cipherAlgorithm(
        EVP_CIPHER_fetch(nullptr, cipher.c_str(), nullptr), EVP_CIPHER_free);
    OpenSslPtr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> context(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!cipherAlgorithm || !context)
    {
        return CKR_DEVICE_ERROR;
    }
    EVP_CIPHER_CTX_set_flags(context.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (EVP_CipherInit_ex2(context.get(), cipherAlgorithm.get(), wrappingKey->secretValue.data(),
            nullptr, unwrap ? 0 : 1, nullptr) <= 0)
    {
        return CKR_DEVICE_ERROR;
    }
    size_t requiredLength = unwrap
        ? inputLength
        : (mechanism->mechanism == CKM_AES_KEY_WRAP ? inputLength + 8
                                                    : ((inputLength + 7) / 8) * 8 + 8);
    if (!output)
    {
        *outputLength = requiredLength;
        return CKR_OK;
    }
    if (*outputLength < requiredLength)
    {
        *outputLength = requiredLength;
        return CKR_BUFFER_TOO_SMALL;
    }
    int written = 0, tail = 0;
    if (EVP_CipherUpdate(context.get(), output, &written, input, (int)inputLength) <= 0 ||
        EVP_CipherFinal_ex(context.get(), output + written, &tail) <= 0)
    {
        return unwrap ? CKR_ENCRYPTED_DATA_INVALID : CKR_DEVICE_ERROR;
    }
    *outputLength = written + tail;
    return CKR_OK;
}

static std::vector<unsigned char> serializeKeyForWrapping(Object* object)
{
    if (object->objectClass == CKO_SECRET_KEY)
    {
        return object->secretValue;
    }
    if (object->objectClass != CKO_PRIVATE_KEY || !object->asymmetricKey)
    {
        return {};
    }
    OpenSslPtr<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free> info(
        EVP_PKEY2PKCS8(object->asymmetricKey.get()), PKCS8_PRIV_KEY_INFO_free);
    if (!info)
    {
        return {};
    }
    int derLength = i2d_PKCS8_PRIV_KEY_INFO(info.get(), nullptr);
    if (derLength <= 0)
    {
        return {};
    }
    std::vector<unsigned char> bytes(derLength);
    auto cursor = bytes.data();
    i2d_PKCS8_PRIV_KEY_INFO(info.get(), &cursor);
    return bytes;
}

CK_RV WrapKey(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism,
    CK_OBJECT_HANDLE wrappingHandle, CK_OBJECT_HANDLE keyHandle, CK_BYTE_PTR output,
    CK_ULONG_PTR outputLength)
{
    if (!findSession(sessionHandle))
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!outputLength)
    {
        return CKR_ARGUMENTS_BAD;
    }
    auto *wrappingKey = findObject(sessionHandle, wrappingHandle),
         *key = findObject(sessionHandle, keyHandle);
    if (!wrappingKey || !key)
    {
        return CKR_KEY_HANDLE_INVALID;
    }
    if (auto access = requireUserLogin(sessionHandle); access != CKR_OK)
    {
        return access;
    }
    if (!policyValue(*wrappingKey, CKA_WRAP))
    {
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }
    if (!policyValue(*key, CKA_EXTRACTABLE))
    {
        return CKR_KEY_UNEXTRACTABLE;
    }
    auto raw = serializeKeyForWrapping(key);
    if (raw.empty())
    {
        return CKR_KEY_TYPE_INCONSISTENT;
    }
    size_t length = *outputLength;
    auto result =
        aesKeyWrap(false, mechanism, wrappingKey, raw.data(), raw.size(), output, &length);
    *outputLength = length;
    return result;
}

CK_RV UnwrapKey(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism,
    CK_OBJECT_HANDLE wrappingHandle, CK_BYTE_PTR input, CK_ULONG inputLength,
    CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_OBJECT_HANDLE_PTR keyHandle)
{
    if (!findSession(sessionHandle))
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!input || !keyHandle || (!attributes && attributeCount))
    {
        return CKR_ARGUMENTS_BAD;
    }
    auto* wrappingKey = findObject(sessionHandle, wrappingHandle);
    if (!wrappingKey)
    {
        return CKR_KEY_HANDLE_INVALID;
    }
    if (auto access = requireUserLogin(sessionHandle); access != CKR_OK)
    {
        return access;
    }
    if (!policyValue(*wrappingKey, CKA_UNWRAP))
    {
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }
    auto valid = validateCreationTemplate(attributes, attributeCount);
    if (valid)
    {
        return valid;
    }
    size_t length = inputLength;
    std::vector<unsigned char> raw(length);
    auto result = aesKeyWrap(true, mechanism, wrappingKey, input, inputLength, raw.data(), &length);
    if (result)
    {
        return result;
    }
    raw.resize(length);
    auto objectClass =
        templateUnsigned(attributes, attributeCount, CKA_CLASS).value_or(CKO_SECRET_KEY);
    std::string label = templateString(attributes, attributeCount, CKA_LABEL, "unwrapped-key");
    if (objectClass == CKO_SECRET_KEY)
    {
        if (raw.size() != 16 && raw.size() != 24 && raw.size() != 32)
        {
            return CKR_KEY_SIZE_RANGE;
        }
        Object object;
        object.handle = runtime.nextObjectHandle++;
        object.objectClass = CKO_SECRET_KEY;
        object.keyType = CKK_AES;
        object.label = label;
        object.id = templateString(
            attributes, attributeCount, CKA_ID, std::to_string(runtime.nextObjectHandle));
        object.path =
            (sessionSlot(sessionHandle).directory / "symmetric" / (safeFilename(label) + ".key"))
                .string();
        object.secretValue = raw;
        result = applyCreationTemplate(object, sessionHandle, attributes, attributeCount);
        if (result)
        {
            return result;
        }
        if (templateUnsigned(attributes, attributeCount, CKA_VALUE_LEN).value_or(raw.size()) !=
            raw.size())
        {
            return CKR_TEMPLATE_INCONSISTENT;
        }
        if (!object.ownerSession)
        {
            result = saveSecretKey(object);
            if (result)
            {
                return result;
            }
        }
        auto handle = object.handle;
        runtime.objects.emplace(handle, std::move(object));
        if (!runtime.objects.at(handle).ownerSession)
        {
            result = persistMetadata(runtime.objects.at(handle).path);
            if (result)
            {
                return result;
            }
        }
        *keyHandle = handle;
        return CKR_OK;
    }
    const unsigned char* cursor = raw.data();
    if (objectClass != CKO_PRIVATE_KEY)
    {
        return CKR_TEMPLATE_INCONSISTENT;
    }
    OpenSslPtr<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free> info(
        d2i_PKCS8_PRIV_KEY_INFO(nullptr, &cursor, (long)raw.size()), PKCS8_PRIV_KEY_INFO_free);
    if (!info || cursor != raw.data() + raw.size())
    {
        return CKR_DATA_INVALID;
    }
    EVP_PKEY* key = EVP_PKCS82PKEY(info.get());
    if (!key)
    {
        return CKR_DATA_INVALID;
    }
    Object privatePolicy;
    privatePolicy.objectClass = CKO_PRIVATE_KEY;
    privatePolicy.keyType = keyType(key);
    result = applyCreationTemplate(privatePolicy, sessionHandle, attributes, attributeCount);
    if (result)
    {
        EVP_PKEY_free(key);
        return result;
    }
    fs::path path =
        sessionSlot(sessionHandle).directory / "asymmetric" / (safeFilename(label) + ".p12");
    result = privatePolicy.ownerSession ? CKR_OK
                                        : saveKeyPair(sessionSlot(sessionHandle), path, key, label);
    if (result)
    {
        EVP_PKEY_free(key);
        return result;
    }
    CK_OBJECT_HANDLE privateObjectHandle = runtime.nextObjectHandle;
    registerKeyPair(sessionSlot(sessionHandle).id, label, path, key, nullptr);
    auto id = templateString(
        attributes, attributeCount, CKA_ID, runtime.objects.at(privateObjectHandle).id);
    runtime.objects.at(privateObjectHandle).id = id;
    runtime.objects.at(privateObjectHandle + 1).id = id;
    runtime.objects.at(privateObjectHandle).policy = privatePolicy.policy;
    runtime.objects.at(privateObjectHandle).ownerSession =
        runtime.objects.at(privateObjectHandle + 1).ownerSession = privatePolicy.ownerSession;
    if (privatePolicy.ownerSession)
    {
        runtime.objects.at(privateObjectHandle).path.clear();
        runtime.objects.at(privateObjectHandle + 1).path.clear();
    }
    else
    {
        result = persistMetadata(path.string());
        if (result)
        {
            return result;
        }
    }
    *keyHandle = privateObjectHandle;
    return CKR_OK;
}

} // namespace hsm
